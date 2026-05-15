"""Opencode CLI invocation and output parsing.

The single chokepoint between the scanner and the `opencode` CLI. Every
phase (discovery, dependency, perfile, confirmation, dedup, summary)
calls `call_opencode` or `call_opencode_json`; nothing else shells out.

Two responsibilities:
  - Subprocess management with conservative retry (rate-limit-only) and
    chatlog writing — see `_RETRY_ATTEMPTS` and `_write_chatlog`.
  - Output parsing: `opencode run --format default` prints a human log
    that ends with the model's final message. `extract_model_output`
    strips the log lines; `extract_json` pulls the first JSON value out
    of the remainder, tolerating prose and code fences.

`set_chatlog_dir` MUST be called once per project before any opencode
invocation (cli.scan_project does this). `ensure_scanner_agent_loaded`
MUST be called before the first real LLM call — it is the safety
interlock that keeps `--dangerously-skip-permissions` from escalating
beyond the scanner agent's read-only jail.
"""

import itertools
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path


# Repo root holds opencode.json — the `scanner` agent definition. We pass
# its absolute path via the OPENCODE_CONFIG env var because opencode's
# default discovery ("walk up from cwd to nearest .git") stops *inside*
# the scan target whenever that target is itself a git repo (which it
# almost always is when cloned). Setting OPENCODE_CONFIG bypasses the
# git-based walk and points opencode straight at our agent file.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_OPENCODE_CONFIG_PATH = _REPO_ROOT / "opencode.json"


def _opencode_env() -> dict[str, str]:
    """Return the env dict for the opencode subprocess: parent env plus the
    explicit OPENCODE_CONFIG override."""
    env = os.environ.copy()
    env["OPENCODE_CONFIG"] = str(_OPENCODE_CONFIG_PATH)
    return env


_jail_verified = False


# Chatlog state. set_chatlog_dir() is called once per project from cli.py
# before any LLM invocation, so the directory exists by the time worker
# threads try to write into it. itertools.count is thread-safe; combined
# with phase + thread-id in the filename, we never collide.
_chatlog_dir: Path | None = None
_chatlog_counter = itertools.count(1)


# Bounded retry on suspected rate limits.
#
# opencode hangs (does not exit) on provider 429s — sst/opencode#8203 — so
# we never see a 429 status code from opencode itself. The only thing we
# can do is wait for our own subprocess timeout, then look at the partial
# stderr captured up to that point. With --print-logs --log-level INFO,
# the provider's 429 message lands in stderr before opencode hangs, so we
# can pattern-match for "429" / "rate limit" / "Too Many Requests" and
# retry only when we see them.
#
# What we explicitly do NOT retry:
#   - Timeouts without rate-limit markers in stderr (genuine slow call or
#     unknown hang — retrying probably won't help, and the second timeout
#     just doubles the wall clock).
#   - Nonzero exits (auth failure, bad model slug, malformed prompt,
#     deny-rule trip). None of those are transient.
_RETRY_ATTEMPTS = 2  # extra attempts after the first; 3 total at most
_RETRY_BASE_DELAY = 5  # seconds; doubled per attempt
_RATE_LIMIT_RE = re.compile(
    r"\b429\b|rate[\s-]*limit|too\s+many\s+requests|quota\s+exceeded",
    re.IGNORECASE,
)


def _looks_like_rate_limit(stderr: str) -> bool:
    return bool(_RATE_LIMIT_RE.search(stderr or ""))


def set_chatlog_dir(path: Path | None) -> None:
    """Configure where call_opencode writes per-call logs. Pass None to disable."""
    global _chatlog_dir, _chatlog_counter
    _chatlog_dir = path
    _chatlog_counter = itertools.count(1)
    if path is not None:
        path.mkdir(parents=True, exist_ok=True)


def _slugify_phase(phase: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", phase.lower()).strip("-") or "call"


def _write_chatlog(phase: str, attempt: int, prompt: str, project_dir: str,
                   model: str, stdout: str, stderr: str, returncode: int | None,
                   elapsed: float) -> None:
    if _chatlog_dir is None:
        return
    n = next(_chatlog_counter)
    retry_suffix = "" if attempt == 0 else f"_retry{attempt}"
    fname = f"{n:05d}_{_slugify_phase(phase)}_{threading.get_ident()}{retry_suffix}.log"
    rc_str = "timeout" if returncode is None else str(returncode)
    body = (
        f"# phase={phase} attempt={attempt} model={model} dir={project_dir} "
        f"rc={rc_str} elapsed={elapsed:.1f}s\n"
        f"\n=== PROMPT ===\n{prompt}\n"
        f"\n=== STDOUT ===\n{strip_ansi(stdout)}\n"
        f"\n=== STDERR ===\n{strip_ansi(stderr)}\n"
    )
    try:
        (_chatlog_dir / fname).write_text(body, encoding="utf-8")
    except OSError:
        # Logging must never break the scan.
        pass


def ensure_scanner_agent_loaded() -> None:
    """Fail fast if opencode does not register our `scanner` agent.

    --dangerously-skip-permissions is safe ONLY because the agent's deny
    rules hard-block edit/bash/external_directory. If the agent doesn't
    load (missing opencode.json, wrong path, syntax error) opencode
    silently falls back to the default `build` agent — which has all
    tools enabled and `external_directory: ask`. Combined with skip-
    permissions, that escalates an ambient `ask` into an effective
    `allow`. So we refuse to run unless we can prove the jail loaded.
    """
    global _jail_verified
    if _jail_verified:
        return
    try:
        result = subprocess.run(
            ["opencode", "agent", "list"],
            capture_output=True, text=True, timeout=30,
            env=_opencode_env(),
            cwd=_REPO_ROOT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        sys.exit(f"Could not verify opencode agent registration: {exc}")
    if result.returncode != 0 or "scanner" not in (result.stdout or ""):
        sys.exit(
            "FATAL: the `scanner` agent is not registered with opencode.\n"
            f"  OPENCODE_CONFIG={_OPENCODE_CONFIG_PATH}\n"
            "  Without it, --dangerously-skip-permissions in scanner/opencode_client.py\n"
            "  silently auto-approves the default agent's `ask` rules — bypassing the\n"
            "  intended read-only jail. Refusing to run.\n\n"
            "  Fix: ensure opencode.json exists at the repo root and contains the\n"
            "  `scanner` agent block. Verify with: opencode agent list"
        )
    _jail_verified = True


def call_opencode(prompt: str, project_dir: str, model: str, timeout: int,
                  phase: str = "call") -> str:
    """
    Invoke opencode and return stdout. Returns an ERROR string on failure
    rather than raising, so the scan continues.

    Runs as the `scanner` agent (defined in this repo's opencode.json) so
    the model is jailed to read-only tools within `--dir`. See CLAUDE.md.

    Retry policy is conservative: only timeouts whose stderr contains
    explicit rate-limit markers ("429", "rate limit", "too many requests")
    are retried with exponential backoff. Plain timeouts without those
    markers, and any nonzero exit, return immediately — see the comment
    next to _RETRY_ATTEMPTS for the rationale.
    """
    # Pass the prompt via stdin instead of as an argv entry. Large prompts
    # (notably the business-summary phase, which embeds every kept finding)
    # can exceed ARG_MAX (~128 KB on Linux) and trigger
    # OSError: [Errno 7] Argument list too long. opencode reads the message
    # from stdin when no positional argument is given.
    cmd = [
        "opencode", "run",
        "--dir", project_dir,
        "--model", model,
        "--agent", "scanner",
        "--dangerously-skip-permissions",
        "--print-logs",
        "--log-level", "INFO",
        "--format", "default",
    ]

    last_error = ""
    for attempt in range(_RETRY_ATTEMPTS + 1):
        start = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=_REPO_ROOT,
                env=_opencode_env(),
            )
        except FileNotFoundError:
            sys.exit(
                "'opencode' not found on PATH. Install it (brew install sst/tap/opencode) "
                "and make sure you're authenticated (`opencode auth login`)."
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - start
            partial_stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            partial_stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            _write_chatlog(phase, attempt, prompt, project_dir, model,
                           partial_stdout, partial_stderr, None, elapsed)
            if _looks_like_rate_limit(partial_stderr) and attempt < _RETRY_ATTEMPTS:
                last_error = f"[ERROR] opencode timeout after {timeout}s (rate-limit suspected)"
                time.sleep(_RETRY_BASE_DELAY * (2 ** attempt))
                continue
            # Either no rate-limit markers, or we've used up our retries.
            # Return the original error string the rest of the codebase
            # already recognises.
            return f"[ERROR] opencode timeout after {timeout}s"

        elapsed = time.monotonic() - start
        _write_chatlog(phase, attempt, prompt, project_dir, model,
                       result.stdout or "", result.stderr or "",
                       result.returncode, elapsed)
        if result.returncode == 0:
            return strip_ansi(result.stdout).strip()

        # Nonzero exit: not retried. Auth failure, bad model slug, agent
        # deny-rule trip etc. won't fix themselves on a second attempt.
        stderr_summary = summarize_stderr(result.stderr)
        return f"[ERROR] opencode exit={result.returncode} stderr={stderr_summary}"

    return last_error


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def summarize_stderr(stderr: str) -> str:
    text = strip_ansi(stderr or "").strip()
    if not text:
        return "(no stderr)"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return " | ".join(lines[-8:])[:1000]


_OPENCODE_LOG_PREFIXES = ("→", "✓", "✗", "●", "│", "┌", "└", "├", ">")


def extract_model_output(stdout: str) -> str:
    """
    Drop opencode's own log lines; keep everything that looks like model output.
    """
    lines = strip_ansi(stdout or "").splitlines()
    kept: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            kept.append(line)
            continue
        if stripped.startswith(_OPENCODE_LOG_PREFIXES):
            continue
        kept.append(line)
    return "\n".join(kept).strip()


def extract_json(text: str) -> object | None:
    """
    Parse the first JSON value (object or array) found in text. Tolerates
    surrounding prose and triple-backtick code fences.
    """
    if not text:
        return None
    cleaned = re.sub(r"```(?:json)?\s*", "", text)
    cleaned = cleaned.replace("```", "")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for i, ch in enumerate(cleaned):
        if ch not in "{[":
            continue
        try:
            value, _ = decoder.raw_decode(cleaned[i:])
            return value
        except json.JSONDecodeError:
            continue
    return None


def call_opencode_json(prompt: str, project_dir: str, model: str, timeout: int,
                       retry_nudge: str,
                       phase: str = "call") -> tuple[object | None, str]:
    """
    Call opencode, extract JSON. One retry on parse failure with a short nudge.
    Returns (parsed_value_or_None, raw_combined_output).
    """
    raw = call_opencode(prompt, project_dir, model, timeout, phase=phase)
    if raw.startswith("[ERROR]"):
        return None, raw
    value = extract_json(extract_model_output(raw))
    if value is not None:
        return value, raw

    retry_prompt = prompt + "\n\n" + retry_nudge
    raw2 = call_opencode(retry_prompt, project_dir, model, timeout,
                         phase=f"{phase}-parse-retry")
    if raw2.startswith("[ERROR]"):
        return None, f"{raw}\n\n--- RETRY ---\n{raw2}"
    value = extract_json(extract_model_output(raw2))
    return value, f"{raw}\n\n--- RETRY ---\n{raw2}"
