"""Command-line entry point: arg parsing, per-project dispatch, phase
orchestration (discovery → dependency → per-file → confirmation → dedup)."""

import argparse
import concurrent.futures
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from .config import (
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_EXCLUDE_FILES,
    DEFAULT_EXTENSIONS,
    DEFAULT_MODEL_HEAVY,
    DEFAULT_MODEL_LIGHT,
    DEFAULT_PARALLEL,
)
from .confirmation import confirm_finding
from .dedup import _dedupe_findings, semantic_dedup_pass
from .discovery import discover_all_files, discover_files
from .findings import parse_failure_finding, parse_findings_array
from .opencode_client import (
    call_opencode_json,
    ensure_scanner_agent_loaded,
    set_chatlog_dir,
)
from .perfile import scan_single_file
from .prompts import (
    build_dependency_prompt,
    build_directory_tree,
    build_discovery_prompt,
    build_file_prompt,
    load_developer_feedback,
    load_project_docs,
    load_template,
)
from .report import flush_reports
from . import sca
from .summary import generate_business_summary


_REPO_ROOT = Path(__file__).resolve().parent.parent


_TRUTHY_ENV_VALUES = {"1", "true", "yes", "on"}


def _resolve_feedback_dir(project_dir: Path,
                          args: argparse.Namespace) -> Path | None:
    """Return the SECURITY_SCAN.md file to read for this scan.

    Precedence:
      1. --feedback-dir / SCAN_FEEDBACK_DIR override. Accepts either a
         direct file path or a directory containing SECURITY_SCAN.md.
      2. <project_dir>/SECURITY_SCAN.md.
      3. If exactly one immediate visible subdir of <project_dir> contains
         a SECURITY_SCAN.md, use that. If two or more do, refuse to guess
         (caller logs a warning listing candidates).
    """
    if args.feedback_dir:
        override = Path(args.feedback_dir).resolve()
        candidate = override / "SECURITY_SCAN.md" if override.is_dir() else override
        return candidate if candidate.is_file() else None

    direct = project_dir / "SECURITY_SCAN.md"
    if direct.is_file():
        return direct

    matches = _child_feedback_candidates(project_dir)
    if len(matches) == 1:
        return matches[0]
    return None


def _child_feedback_candidates(project_dir: Path) -> list[Path]:
    """Immediate visible subdirs of project_dir that contain SECURITY_SCAN.md."""
    if not project_dir.is_dir():
        return []
    out: list[Path] = []
    for child in sorted(project_dir.iterdir()):
        if child.name.startswith("."):
            continue
        if not child.is_dir():
            continue
        candidate = child / "SECURITY_SCAN.md"
        if candidate.is_file():
            out.append(candidate)
    return out


def _log_feedback_resolution(project_dir: Path, resolved: Path | None,
                             args: argparse.Namespace) -> None:
    """Print exactly one [Feedback] line so every run is unambiguous about
    whether SECURITY_SCAN.md was loaded and from where."""
    if resolved is not None:
        print(f"[Feedback] Using {resolved}", flush=True)
        return

    if args.feedback_dir:
        override = Path(args.feedback_dir).resolve()
        print(f"[Feedback] None loaded (override path not found: {override}).",
              flush=True)
        return

    direct = project_dir / "SECURITY_SCAN.md"
    candidates = _child_feedback_candidates(project_dir)
    if len(candidates) >= 2:
        listed = ", ".join(str(p) for p in candidates)
        print(
            f"[Feedback] WARNING: not loaded; multiple subdirs contain "
            f"SECURITY_SCAN.md ({listed}). Pass the project subdir directly "
            f"or set --feedback-dir to disambiguate.",
            flush=True,
        )
        return

    print(
        f"[Feedback] None loaded (no SECURITY_SCAN.md at {direct} or any "
        f"immediate subdirectory of {project_dir}).",
        flush=True,
    )


def _resolve_feedback_text(project_dir: Path,
                           args: argparse.Namespace) -> tuple[str, Path | None]:
    """Return (feedback_text, resolved_path). Path is None when no file resolved."""
    feedback_file = _resolve_feedback_dir(project_dir, args)
    if feedback_file is None:
        return "", None
    return load_developer_feedback(feedback_file), feedback_file


def _path_size(path: Path) -> int | None:
    """Return file size, or None if the path disappeared or is unreadable."""
    try:
        return path.stat().st_size
    except OSError:
        return None


def _load_dotenv(path: Path) -> dict[str, str]:
    """Tiny .env parser. KEY=VALUE per line, '#' comments, blanks ignored.
    No quoting / interpolation / multi-line values — keep it boring."""
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


def _env_str(env: dict[str, str], name: str, fallback: str) -> str:
    """Real environment beats .env beats fallback. Empty string = unset."""
    val = os.environ.get(name) or env.get(name) or ""
    return val if val else fallback


def _env_int(env: dict[str, str], name: str, fallback: int) -> int:
    val = os.environ.get(name) or env.get(name) or ""
    if not val:
        return fallback
    try:
        return int(val)
    except ValueError:
        return fallback


def _env_bool(env: dict[str, str], name: str) -> bool:
    val = (os.environ.get(name) or env.get(name) or "").strip().lower()
    return val in _TRUTHY_ENV_VALUES


def parse_args() -> argparse.Namespace:
    # Repo root holds .env (and opencode.json). Load it once per invocation;
    # values become argparse defaults so the --help output stays accurate.
    env = _load_dotenv(Path(__file__).resolve().parent.parent / ".env")

    p = argparse.ArgumentParser(
        description="Agentic white-box security scanner (opencode-only). "
                    "Most settings live in .env at the repo root; CLI flags "
                    "override them when given.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Per-invocation choices — CLI only.
    p.add_argument("--refresh-osv-db", action="store_true",
                   help="Refresh the local OSV/GHSA database via osv-scanner "
                        "(downloads every supported ecosystem; ~1.5–2 GB on "
                        "disk) and exit. Suitable for cron.")
    p.add_argument("project_dirs", nargs="*", default=None, metavar="PROJECT_DIR",
                   help="One or more project directories to scan (default: "
                        "./input/). When multiple are given, each "
                        "gets its own report under "
                        "<output>/<project_name>/vulnerabilities.{md,json}.")
    p.add_argument("--output", "-o", default=None,
                   help="Output base path; .md and .json are written "
                        "(default: ./output/<timestamp>/vulnerabilities)")
    p.add_argument("--dependencies-only", action="store_true",
                   help="Run only dependency audit (skips per-file review).")
    p.add_argument("--dry-run", action="store_true",
                   help="List files that would be scanned, then exit")
    p.add_argument("--print-prompt", default=None, metavar="PHASE",
                   help="Render the prompt for one phase and exit without "
                        "invoking opencode. PHASE is one of "
                        "`discovery`, `dependency`, or `perfile:<relative/path>`. "
                        "Useful for prompt iteration and debugging.")

    # Defaulted-from-.env settings. Each --flag still works as an ad-hoc override.
    # Model selection is .env-only — see SCAN_MODEL_HEAVY / SCAN_MODEL_LIGHT
    # in .env. No --model CLI flag: per-call model overrides are rare and
    # the two-slot split (heavy = assessment, light = post-processing) is
    # awkward to express as a single argv flag.
    p.add_argument("--parallel", type=int,
                   default=_env_int(env, "SCAN_PARALLEL", DEFAULT_PARALLEL),
                   help="Max concurrent opencode calls (env: SCAN_PARALLEL)")
    p.add_argument("--timeout", type=int,
                   default=_env_int(env, "SCAN_TIMEOUT", 300),
                   help="Seconds per opencode call (env: SCAN_TIMEOUT)")
    p.add_argument("--no-auto-refresh-osv-db", action="store_const", const=True,
                   default=_env_bool(env, "SCAN_NO_AUTO_REFRESH_OSV_DB"),
                   help="Disable automatic OSV DB refresh during scans. By "
                        "default a missing or stale DB triggers a refresh "
                        "(~1.5–2 GB on first run) so Phase 1 has full CVE "
                        "ground truth. Use this for cron-driven setups that "
                        "refresh on a separate schedule, or for air-gapped "
                        "hosts (env: SCAN_NO_AUTO_REFRESH_OSV_DB).")
    p.add_argument("--osv-db-dir",
                   default=_env_str(env, "SCAN_OSV_DB_DIR", "") or None,
                   help="Local OSV/GHSA database directory used by osv-scanner "
                        "(env: SCAN_OSV_DB_DIR; default ./.security-scan-cache/osv).")

    # Phase skips: argparse `store_true` would force False as default, which
    # would always override the env value. Use `store_const` against a default
    # taken from .env, so the env wins unless --skip-* is given on the CLI.
    for flag, env_name, help_text in [
        ("--skip-discovery",     "SCAN_SKIP_DISCOVERY",     "Skip Phase 0 project discovery"),
        ("--skip-dependencies",  "SCAN_SKIP_DEPENDENCIES",  "Skip Phase 1 dependency audit"),
        ("--skip-confirmation",  "SCAN_SKIP_CONFIRMATION",  "Skip the per-finding confirmation pass"),
        ("--skip-dedup",         "SCAN_SKIP_DEDUP",         "Skip the per-file semantic dedup pass"),
        ("--skip-sca",           "SCAN_SKIP_SCA",           "Skip osv-scanner ground-truth CVE injection in Phase 1"),
    ]:
        p.add_argument(
            flag, action="store_const", const=True,
            default=_env_bool(env, env_name),
            help=f"{help_text} (env: {env_name})",
        )

    args = p.parse_args()
    # Settings that are project-stable rather than per-call live in `.env`
    # only — no CLI flag — so the help output stays focused on what
    # actually varies between runs. Tests construct argparse Namespaces
    # directly, so fixing the values on the namespace here is consistent
    # with how the rest of the codebase reads them.
    args.max_file_size = _env_int(env, "SCAN_MAX_FILE_SIZE", 100_000)
    args.extensions = _env_str(env, "SCAN_EXTENSIONS", "") or None
    args.exclude_dirs = _env_str(env, "SCAN_EXCLUDE_DIRS", "") or None
    args.feedback_dir = _env_str(env, "SCAN_FEEDBACK_DIR", "") or None
    args.prompt_dir = None  # only the canonical ./prompts/ is supported

    # Two-slot model resolution. SCAN_MODEL_HEAVY / SCAN_MODEL_LIGHT are
    # the canonical settings; legacy SCAN_MODEL fills any unset slot so
    # existing .env files keep working until users opt into the split.
    legacy_single = _env_str(env, "SCAN_MODEL", "")
    args.model_heavy = _env_str(env, "SCAN_MODEL_HEAVY",
                                legacy_single or DEFAULT_MODEL_HEAVY)
    args.model_light = _env_str(env, "SCAN_MODEL_LIGHT",
                                legacy_single or DEFAULT_MODEL_LIGHT)
    return args


def resolve_prompt_path(prompt_dir: str | None, name: str) -> Path:
    # Prompts live next to the top-level entry point, not inside the package.
    base = Path(prompt_dir) if prompt_dir else Path(__file__).resolve().parent.parent / "prompts"
    return base / name


def _resolve_osv_db_dir(args: argparse.Namespace) -> Path:
    """Honour --osv-db-dir / SCAN_OSV_DB_DIR if set, else use the package
    default (./.security-scan-cache/osv/)."""
    if args.osv_db_dir:
        return Path(args.osv_db_dir).expanduser().resolve()
    env_override = os.environ.get("SCAN_OSV_DB_DIR", "").strip()
    if env_override:
        return Path(env_override).expanduser().resolve()
    return sca._DEFAULT_DB_DIR


def main() -> None:
    args = parse_args()

    # Refresh-only mode: download OSV DB across every supported ecosystem,
    # then exit. Independent of any scan; runs without opencode.
    if args.refresh_osv_db:
        sys.exit(sca.refresh_offline_db(_resolve_osv_db_dir(args)))

    # Refuse to run unless the read-only scanner agent is registered. See
    # ensure_scanner_agent_loaded() for the rationale — short version: the
    # --dangerously-skip-permissions flag is only safe under our deny rules.
    # --dry-run and --print-prompt never reach opencode, so the preflight
    # is unnecessary noise in those modes.
    if not args.dry_run and not args.print_prompt:
        ensure_scanner_agent_loaded()

    script_dir = Path(__file__).resolve().parent.parent
    input_root = script_dir / "input"
    raw_dirs = args.project_dirs or []
    if not raw_dirs:
        # input/ is the default scan target — a single project root.
        if not input_root.is_dir():
            sys.exit(
                f"Default input directory not found: {input_root}\n"
                "Create input/ and drop the project to scan into it."
            )
        visible = [
            p for p in input_root.iterdir()
            if not p.name.startswith(".")
        ]
        if not visible:
            sys.exit(
                f"input/ is empty: {input_root}\n"
                "Drop (or symlink) the project to scan into it, or pass a path."
            )
        raw_dirs = [str(input_root)]

    project_dirs: list[Path] = []
    for raw in raw_dirs:
        pd = Path(raw).resolve()
        if not pd.is_dir():
            sys.exit(
                f"Project directory not found: {pd}\n"
                "Tip: drop the application to scan into "
                "input/ or pass an explicit path."
            )
        project_dirs.append(pd)

    is_multi_project = len(project_dirs) > 1

    run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

    # Resolve per-project report paths.
    # --output explicitly given → honor it literally (no timestamp injection).
    # Single-dir default: ./output/<timestamp>/vulnerabilities.{md,json}
    # Multi-dir default:  ./output/<timestamp>/<project>/vulnerabilities.{md,json}
    if is_multi_project:
        if args.output:
            output_root = Path(args.output).resolve()
        else:
            output_root = script_dir / "output" / run_timestamp
        report_paths = [
            output_root / pd.name / "vulnerabilities" for pd in project_dirs
        ]
    else:
        if args.output:
            single_base = Path(args.output).resolve()
        else:
            single_base = script_dir / "output" / run_timestamp / "vulnerabilities"
        report_paths = [single_base]

    if args.print_prompt:
        # First project only — printing prompts for multiple projects is
        # ambiguous and the user can re-run per-project if they need it.
        _print_prompt(project_dirs[0], args)
        return

    for project_index, (project_dir, output_base) in enumerate(zip(project_dirs, report_paths), 1):
        md_path = output_base.with_suffix(".md")
        json_path = output_base.with_suffix(".json")
        if is_multi_project:
            print(f"\n{'=' * 70}\n[{project_index}/{len(project_dirs)}] Scanning {project_dir}\n{'=' * 70}")
        scan_project(project_dir, md_path, json_path, args)


def _print_prompt(project_dir: Path, args: argparse.Namespace) -> None:
    """Render the prompt for one phase and write it to stdout, without
    invoking opencode. Useful for prompt iteration and debugging.

    `args.print_prompt` is one of:
      - "discovery"       — Phase 0
      - "dependency"      — Phase 1 (SCA block left empty; would normally
                            be filled by `_run_sca` at scan time)
      - "perfile:<path>"  — Phase 2 for one source file (path relative
                            to project_dir)
    """
    spec = (args.print_prompt or "").strip()
    if not spec:
        sys.exit("--print-prompt requires a phase name.")

    # Prompts read manifests + the directory tree, not the per-file
    # extension-filtered list, so SCAN_EXTENSIONS doesn't apply here.
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if args.exclude_dirs:
        exclude_dirs.update(d.strip() for d in args.exclude_dirs.split(","))
    all_files = discover_all_files(str(project_dir), exclude_dirs)
    feedback_text, _ = _resolve_feedback_text(project_dir, args)

    if spec == "discovery":
        path = resolve_prompt_path(args.prompt_dir, "discovery-prompt.md")
        docs_text = load_project_docs(project_dir)
        prompt = build_discovery_prompt(
            load_template(path), all_files, project_dir, docs_text,
        )
    elif spec == "dependency":
        path = resolve_prompt_path(args.prompt_dir, "dependency-prompt.md")
        prompt = build_dependency_prompt(
            load_template(path), all_files, project_dir,
            feedback_text, sca_results="",
        )
    elif spec.startswith("perfile:"):
        rel = spec[len("perfile:"):].strip()
        if not rel:
            sys.exit("--print-prompt perfile:<path> requires a file path.")
        target = (project_dir / rel).resolve()
        if not target.is_file():
            sys.exit(f"File not found: {target}")
        path = resolve_prompt_path(args.prompt_dir, "security-prompt.md")
        tree_text = build_directory_tree(all_files, project_dir)
        prompt = build_file_prompt(
            load_template(path),
            "(no project brief — print-prompt does not run Phase 0)",
            tree_text, feedback_text, target, project_dir,
        )
    else:
        sys.exit(
            f"Unknown --print-prompt phase: {spec!r}. "
            "Expected one of: discovery, dependency, perfile:<relative/path>."
        )

    print(prompt)


def _run_sca(project_dir: Path, args: argparse.Namespace,
             exclude_dirs: set[str]) -> tuple[str, dict[str, object]]:
    """Run the Phase 1 SCA prelude. Returns (sca_results_text, sca_meta).

    Stamped-degrade contract: any failure produces an empty result text and
    a metadata dict that names the reason. The scan continues unaltered;
    the dependency-prompt template tells the LLM how to handle an empty
    SCA block (fall back to training-data knowledge for direct deps).
    """
    db_dir = _resolve_osv_db_dir(args)
    state = sca.db_state(db_dir)

    # Auto-refresh when the DB is missing or stale. Trades a one-time ~1.5–2 GB
    # download (or a fast incremental refresh) for "scans are always as
    # complete as possible". For cron-driven setups the DB stays fresh and
    # this branch never fires. For air-gapped setups refresh fails and we
    # fall through to the stamped-degrade contract. Users who prefer the old
    # opt-in behavior (e.g. CI without a separate cron job, but with stable
    # network constraints) can pass --no-auto-refresh-osv-db /
    # SCAN_NO_AUTO_REFRESH_OSV_DB=1.
    auto_refresh_disabled = getattr(args, "no_auto_refresh_osv_db", False)
    if (state.missing or state.stale) and auto_refresh_disabled:
        if state.missing:
            print(f"[SCA] no OSV DB at {db_dir}. Auto-refresh disabled "
                  "(--no-auto-refresh-osv-db). Run 'python security-scan.py "
                  "--refresh-osv-db' to enable Phase 1 ground-truth CVE data. "
                  "Continuing without SCA.", flush=True)
            meta = state.as_dict()
            meta["reason"] = "db_missing"
            return "", meta
        print(f"[SCA] OSV DB is {state.db_age_hours}h old (> "
              f"{sca._DB_STALE_HOURS}h stale threshold). Auto-refresh "
              "disabled (--no-auto-refresh-osv-db). Treating as unavailable.",
              flush=True)
        meta = state.as_dict()
        meta["reason"] = "db_stale"
        return "", meta

    if state.missing or state.stale:
        if state.missing:
            print(f"[SCA] OSV DB missing at {db_dir}. Auto-refreshing now — "
                  "the initial download is ~1.5–2 GB and may take several "
                  "minutes. Subsequent runs reuse the cache.", flush=True)
        else:
            print(f"[SCA] OSV DB is {state.db_age_hours}h old (> {sca._DB_STALE_HOURS}h "
                  "stale threshold). Auto-refreshing now — incremental "
                  "refreshes are usually fast.", flush=True)
        rc = sca.refresh_offline_db(db_dir=db_dir)
        if rc != 0:
            # Refresh failed (network, sha mismatch, etc.). Stamped-degrade.
            meta = sca.db_state(db_dir).as_dict()
            meta["reason"] = "refresh_failed"
            return "", meta
        # Re-stat after a successful refresh so metadata reflects the new age.
        state = sca.db_state(db_dir)

    bin_path = sca.ensure_osv_scanner()
    if bin_path is None:
        meta = state.as_dict()
        meta["reason"] = "binary_unavailable"
        return "", meta

    result = sca.run_osv_scan(project_dir, bin_path, db_dir, sorted(exclude_dirs))
    # `no_sources` = osv-scanner ran fine, the project just has no manifests
    # the tool extracts (pure scripts, custom build systems, NuGet
    # `packages.config` only, etc.). Stamp `available: True` because SCA
    # itself didn't fail — the report renders a neutral note instead of the
    # alarming "unavailable" framing.
    if result.metadata.get("no_sources"):
        meta = state.as_dict()
        meta.update(result.metadata)
        meta["available"] = True
        meta["reason"] = None
        return "", meta

    if not result.json_text:
        meta = state.as_dict()
        meta["reason"] = result.metadata.get("error", "scan_failed")
        meta.update(result.metadata)
        return "", meta

    meta = state.as_dict()
    meta.update(result.metadata)
    meta["reason"] = None
    return result.json_text, meta


def scan_project(project_dir: Path, md_path: Path, json_path: Path,
                 args: argparse.Namespace) -> None:
    extensions = DEFAULT_EXTENSIONS
    if args.extensions:
        extensions = {
            e.strip() if e.strip().startswith(".") else f".{e.strip()}"
            for e in args.extensions.split(",") if e.strip()
        }
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if args.exclude_dirs:
        exclude_dirs.update(d.strip() for d in args.exclude_dirs.split(","))

    files = discover_files(str(project_dir), extensions, exclude_dirs, DEFAULT_EXCLUDE_FILES)
    all_files = discover_all_files(str(project_dir), exclude_dirs)

    print(f"Discovered {len(files)} source file(s), {len(all_files)} total file(s) in {project_dir}")

    if args.dry_run:
        print("\nSource files that would be scanned:\n")
        for source_file in files:
            size = _path_size(source_file)
            rel = source_file.relative_to(project_dir)
            if size is None:
                print(f"  [   skip]  {rel} (unavailable)")
                continue
            print(f"  [{size:>7,} B]  {rel}")
        return

    # Create report directory only when we're actually going to write reports.
    md_path.parent.mkdir(parents=True, exist_ok=True)

    # Persist a per-call chatlog (prompt + stdout + stderr + timing) next to
    # vulnerabilities.md. Always on — see CLAUDE.md "stable and predictable".
    set_chatlog_dir(md_path.parent / "chatlogs")
    sca.set_chatlog_dir(md_path.parent / "chatlogs")

    discovery_path = resolve_prompt_path(args.prompt_dir, "discovery-prompt.md")
    dependency_path = resolve_prompt_path(args.prompt_dir, "dependency-prompt.md")
    security_path = resolve_prompt_path(args.prompt_dir, "security-prompt.md")
    confirmation_path = resolve_prompt_path(args.prompt_dir, "confirmation-prompt.md")
    dedup_path = resolve_prompt_path(args.prompt_dir, "dedup-prompt.md")
    summary_path = resolve_prompt_path(args.prompt_dir, "summary-prompt.md")
    handling_standard_path = resolve_prompt_path(
        args.prompt_dir, "context/vulnerability-handling-standard.md"
    )

    start = time.time()
    all_findings: list[dict] = []
    brief: object | None = None
    # Mutated by the Phase 1 prelude below; current_metadata() picks up
    # the latest value at flush time so partial reports already record
    # SCA state when Ctrl-C interrupts mid-scan.
    sca_meta: dict[str, object] = {"available": False, "reason": "skipped"}

    def current_metadata(scanned: int, skipped: int) -> dict:
        return {
            "project": str(project_dir),
            "model": {"heavy": args.model_heavy, "light": args.model_light},
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration": f"{time.time() - start:.1f}s",
            "files_discovered": len(files),
            "files_scanned": scanned,
            "files_skipped": skipped,
            "sca": dict(sca_meta),
        }

    def flush(scanned: int, skipped: int) -> None:
        flush_reports(md_path, json_path, all_findings, brief, current_metadata(scanned, skipped))

    # Write empty report up front so flushes during Ctrl-C produce a valid file.
    flush(0, 0)

    # ---- Phase 0: Discovery ----
    if not args.skip_discovery and not args.dependencies_only:
        if not discovery_path.is_file():
            sys.exit(f"Discovery prompt not found: {discovery_path}")
        print("\n[Phase 0] Running project discovery ...", flush=True)
        docs_text = load_project_docs(project_dir)
        if docs_text:
            doc_blocks = docs_text.count("=== ")
            print(f"[Phase 0] Loaded {doc_blocks} project doc(s) for context "
                  f"({len(docs_text):,} chars).", flush=True)
        else:
            print("[Phase 0] No project docs found at project root.", flush=True)
        prompt = build_discovery_prompt(
            load_template(discovery_path), all_files, project_dir, docs_text,
        )
        nudge = ("Your previous response could not be parsed. Respond with ONLY the "
                 "JSON object matching the schema. No prose, no code fences.")
        value, _raw = call_opencode_json(
            prompt, str(project_dir), args.model_heavy, args.timeout * 2, nudge,
            phase="discovery",
        )
        if isinstance(value, dict):
            brief = value
            print("[Phase 0] Brief acquired.")
        else:
            print("[Phase 0] WARNING: discovery did not return parseable JSON. Continuing without brief.")
            brief = None
        flush(0, 0)

    brief_text = json.dumps(brief, indent=2) if isinstance(brief, dict) else "(no project brief available)"
    tree_text = build_directory_tree(all_files, project_dir)
    feedback_text, feedback_path = _resolve_feedback_text(project_dir, args)
    _log_feedback_resolution(project_dir, feedback_path, args)

    # ---- Phase 1 prelude: osv-scanner ground-truth CVE injection ----
    sca_results_text = ""
    if not args.skip_dependencies and not args.skip_sca:
        sca_results_text, sca_meta = _run_sca(project_dir, args, exclude_dirs)
    elif args.skip_sca:
        sca_meta = {"available": False, "reason": "skipped_via_flag"}

    # ---- Phase 1: Dependency audit ----
    if not args.skip_dependencies:
        if not dependency_path.is_file():
            print(f"[Phase 1] Dependency prompt not found at {dependency_path}; skipping.")
        else:
            print("\n[Phase 1] Running dependency audit ...", flush=True)
            prompt = build_dependency_prompt(
                load_template(dependency_path), all_files, project_dir,
                feedback_text, sca_results_text,
            )
            nudge = ("Your previous response could not be parsed. Respond with ONLY the JSON "
                     "object matching the schema (including stack and findings array).")
            value, _raw = call_opencode_json(
                prompt, str(project_dir), args.model_heavy, args.timeout * 2, nudge,
                phase="dependency",
            )
            dep_findings = parse_findings_array(value, "Dependency Audit")
            all_findings.extend(dep_findings)
            print(f"[Phase 1] {len(dep_findings)} dependency finding(s).")
            flush(0, 0)

    if args.dependencies_only:
        print("\nDone (dependencies-only).")
        finalize_and_report(all_findings, brief, brief_text, tree_text,
                            feedback_text,
                            md_path, json_path,
                            args, confirmation_path, dedup_path, summary_path,
                            handling_standard_path,
                            project_dir,
                            0, 0, current_metadata)
        return

    # ---- Phase 2: Per-file ----
    work_items: list[tuple[int, Path]] = []
    skipped_count = 0
    for file_index, source_file in enumerate(files, 1):
        size = _path_size(source_file)
        if size is None:
            print(f"  [{file_index}/{len(files)}] SKIP (unavailable) {source_file.relative_to(project_dir)}")
            skipped_count += 1
            continue
        if size == 0:
            skipped_count += 1
            continue
        if size > args.max_file_size:
            print(f"  [{file_index}/{len(files)}] SKIP (too large: {size:,} B) {source_file.relative_to(project_dir)}")
            skipped_count += 1
            continue
        work_items.append((file_index, source_file))

    scanned_count = 0
    if work_items:
        print(f"\n[Phase 2] Reviewing {len(work_items)} file(s) with up to {args.parallel} parallel calls.\n", flush=True)
        if not security_path.is_file():
            sys.exit(f"Security prompt not found: {security_path}")
        template = load_template(security_path)

        max_workers = min(args.parallel, len(work_items))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    scan_single_file, filepath, project_dir, template,
                    brief_text, tree_text, feedback_text,
                    args.model_heavy, args.timeout
                ): (file_index, filepath)
                for file_index, filepath in work_items
            }
            for future in concurrent.futures.as_completed(futures):
                file_index, filepath = futures[future]
                try:
                    findings, _raw = future.result()
                except Exception as exc:
                    findings = [parse_failure_finding(
                        str(filepath.relative_to(project_dir)),
                        f"worker exception: {exc}"
                    )]
                all_findings.extend(findings)
                scanned_count += 1
                flush(scanned_count, skipped_count)
                print(f"  [{file_index}/{len(files)}] {filepath.relative_to(project_dir)} — "
                      f"{len(findings)} finding(s)", flush=True)

    # ---- Confirmation + dedup + final flush ----
    finalize_and_report(all_findings, brief, brief_text, tree_text,
                        feedback_text,
                        md_path, json_path,
                        args, confirmation_path, dedup_path, summary_path,
                        handling_standard_path,
                        project_dir,
                        scanned_count, skipped_count, current_metadata)


def finalize_and_report(all_findings: list[dict], brief: object, brief_text: str,
                        tree_text: str, feedback_text: str,
                        md_path: Path, json_path: Path, args,
                        confirmation_path: Path, dedup_path: Path,
                        summary_path: Path,
                        handling_standard_path: Path,
                        project_dir: Path,
                        scanned: int, skipped: int, metadata_fn) -> None:
    # Dependency Audit findings come from osv-scanner's deterministic
    # version-range matching against an offline OSV/GHSA snapshot. They are
    # not LLM hypotheses and do not need re-verification — mark them
    # confirmed up front and only run the LLM confirmation over per-file
    # findings.
    deterministic_idxs = [
        i for i, f in enumerate(all_findings)
        if f.get("phase") == "Dependency Audit"
    ]
    confirmable_idxs = [
        i for i, f in enumerate(all_findings)
        if f.get("phase") != "Dependency Audit"
    ]
    for i in deterministic_idxs:
        all_findings[i]["confidence"] = "confirmed"
        all_findings[i]["confirmation_note"] = (
            "osv-scanner advisory match — deterministic ground truth, "
            "no LLM re-verification."
        )

    findings_count_before_confirmation = len(confirmable_idxs)
    if not args.skip_confirmation and confirmable_idxs:
        if not confirmation_path.is_file():
            print(f"\n[Confirmation] Prompt not found at {confirmation_path}; skipping.")
        else:
            print(
                f"\n[Confirmation] Re-verifying {findings_count_before_confirmation} per-file finding(s) "
                "before false-positive filtering and deduplication "
                f"(skipping {len(deterministic_idxs)} deterministic dependency finding(s)) ...",
                flush=True,
            )
            template = load_template(confirmation_path)
            max_workers = min(args.parallel, len(confirmable_idxs))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        confirm_finding, all_findings[idx], brief_text, tree_text,
                        feedback_text, template, str(project_dir),
                        args.model_heavy, args.timeout
                    ): idx
                    for idx in confirmable_idxs
                }
                for future in concurrent.futures.as_completed(futures):
                    idx = futures[future]
                    try:
                        all_findings[idx] = future.result()
                    except Exception as exc:
                        all_findings[idx]["confidence"] = "likely"
                        all_findings[idx]["confirmation_note"] = f"confirmation error: {exc}"
                    flush_reports(md_path, json_path, all_findings, brief,
                                  metadata_fn(scanned, skipped))
    else:
        for i in confirmable_idxs:
            if not all_findings[i].get("confidence"):
                all_findings[i]["confidence"] = "likely"
                all_findings[i]["confirmation_note"] = "Confirmation pass skipped."

    kept_after_confirmation = sum(1 for f in all_findings if not f.get("dropped"))
    dropped_after_confirmation = sum(1 for f in all_findings if f.get("dropped"))
    if findings_count_before_confirmation:
        print(
            "[Confirmation] Result: "
            f"{kept_after_confirmation} kept for the report; "
            f"{dropped_after_confirmation} dropped as false positive(s).",
            flush=True,
        )

    # ---- Deterministic dedup pass ----
    if all_findings:
        visible = [f for f in all_findings if not f.get("dropped")]
        dropped = [f for f in all_findings if f.get("dropped")]
        deduped_visible, deterministic_collapsed = _dedupe_findings(visible)
        all_findings[:] = deduped_visible + dropped
        if deterministic_collapsed:
            print(
                "[Dedup] Deterministic result: "
                f"{len(visible)} kept finding(s) -> {len(deduped_visible)} kept finding(s); "
                f"collapsed {len(deterministic_collapsed)} exact/near duplicate report(s).",
                flush=True,
            )
        else:
            print(
                f"[Dedup] Deterministic result: {len(visible)} kept finding(s); "
                "no exact/near duplicates collapsed.",
                flush=True,
            )

    # ---- Semantic dedup pass ----
    if not args.skip_dedup and all_findings:
        if not dedup_path.is_file():
            print(f"\n[Dedup] Prompt not found at {dedup_path}; skipping semantic dedup.")
        else:
            before = sum(1 for f in all_findings if not f.get("dropped"))
            dropped_before = sum(1 for f in all_findings if f.get("dropped"))
            template = load_template(dedup_path)
            new_list = semantic_dedup_pass(
                all_findings, brief_text, tree_text, template, str(project_dir),
                args.model_light, args.timeout, args.parallel
            )
            all_findings[:] = new_list
            after = sum(1 for f in all_findings if not f.get("dropped"))
            print(
                "[Dedup] Semantic result: "
                f"{before} kept finding(s) -> {after} kept finding(s); "
                f"collapsed {before - after} duplicate report(s). "
                f"Dropped false positive(s) unchanged: {dropped_before}.",
                flush=True,
            )
    elif args.skip_dedup and all_findings:
        visible_count = sum(1 for f in all_findings if not f.get("dropped"))
        print(
            f"[Dedup] Semantic dedup skipped; {visible_count} kept finding(s) remain after deterministic dedup.",
            flush=True,
        )

    metadata = metadata_fn(scanned, skipped)
    business_summary = ""
    if summary_path.is_file() and handling_standard_path.is_file():
        print("\n[Summary] Writing business-readable summary ...", flush=True)
        template = load_template(summary_path)
        handling_standard = load_template(handling_standard_path)
        business_summary = generate_business_summary(
            template, handling_standard, all_findings, brief_text, feedback_text, metadata,
            str(_REPO_ROOT), args.model_light, args.timeout
        )
    else:
        missing = [
            str(path) for path in (summary_path, handling_standard_path)
            if not path.is_file()
        ]
        print(f"\n[Summary] Required prompt context missing: {', '.join(missing)}")
        business_summary = (
            "The business summary could not be generated because the summary "
            "prompt or vulnerability handling standard context is missing. Use "
            "the severity table and detailed findings below as the authoritative "
            "scanner output."
        )

    flush_reports(md_path, json_path, all_findings, brief, metadata, business_summary)
    confirmed = sum(1 for f in all_findings if f.get("confidence") == "confirmed" and not f.get("dropped"))
    likely = sum(1 for f in all_findings if f.get("confidence") == "likely" and not f.get("dropped"))
    dropped_count = sum(1 for f in all_findings if f.get("dropped"))
    report_total = confirmed + likely
    print("\nDone.")
    print(
        "  Finding count ledger: "
        f"{findings_count_before_confirmation} raw -> "
        f"{report_total} shown in the report "
        f"({confirmed} confirmed, {likely} likely) + "
        f"{dropped_count} dropped false positive(s)."
    )
    print(f"  Report: {md_path}")
    print(f"  JSON:   {json_path}")
