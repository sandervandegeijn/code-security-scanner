"""Software Composition Analysis (SCA) wrapper around `osv-scanner`.

Phase 1's LLM call cannot reach the network (the `scanner` agent jail
denies `webfetch`), so its CVE knowledge is bounded by training cutoff.
This module runs Google's offline `osv-scanner` against the project on
the host (outside the jail) and feeds the deterministic results into
the dependency-prompt as ground truth — the LLM only has to reason
about exploitability and severity, never about version-range matching.

Lifecycle (decisions locked in the design plan):

  - Binary: auto-downloaded, version-pinned, sha256-verified, cached at
    <repo_root>/.security-scan-cache/bin/osv-scanner-v<pinned>. Override
    with SCAN_OSV_SCANNER_BIN. The cache directory is gitignored.
  - DB: never refreshed during a normal scan. `python security-scan.py
    --refresh-osv-db` (cron-friendly) is the only thing that downloads.
    The scan reads from $SCAN_OSV_DB_DIR (default
    <repo_root>/.security-scan-cache/osv/).
  - Failure mode: stamped-degrade. If the binary is missing, the DB is
    missing, or the DB is older than _DB_STALE_HOURS, the scan still
    runs — it just emits an empty SCA block plus a `metadata.sca`
    record naming the reason, so triagers know whether "no Phase 1
    CVEs" means clean or unverified.
  - Coverage: `--refresh-osv-db` pulls every ecosystem osv-scanner
    supports — no project-specific filtering. ~1.5–2 GB on disk; trades
    space for "works for any stack without detection logic".

Bumping the pinned version: download all five release artefacts, compute
sha256, paste into _OSV_SCANNER_SHA256, bump _OSV_SCANNER_VERSION, run
tests. See CLAUDE.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


# --- Pinned osv-scanner release ----------------------------------------------
# Bump procedure documented in the module docstring and CLAUDE.md.
_OSV_SCANNER_VERSION = "2.3.6"
_OSV_SCANNER_SHA256: dict[tuple[str, str], str] = {
    ("darwin", "amd64"):  "d5c91db387e0559b12136106bce5a57dbcea6fac22942721bd25b2334b28db28",
    ("darwin", "arm64"):  "3d7a12f4349a9e8f822513e5544d4a747ab53b7225d4bf5a2d00211cbc9dfe19",
    ("linux", "amd64"):   "f689e183ef0d573d2459738aae457d411a26241ae58b5088de1af288b3355604",
    ("linux", "arm64"):   "e6ab0955cc906f308704575a608d28e55068d00c7fa7f47797131c89b30c0373",
    ("windows", "amd64"): "14856196d681e18238b41d4741bbe0558bef157c4b3b49d618528294afebe19f",
}

_RELEASE_URL_TEMPLATE = (
    "https://github.com/google/osv-scanner/releases/download/"
    "v{version}/osv-scanner_{os}_{arch}{ext}"
)


# osv-scanner v2 ships with default plugin presets `lockfile, sbom, directory`
# which only recognise resolved-version manifests (`packages.lock.json`,
# `Cargo.lock`, …). Bare manifests like `.csproj` (PackageReference items),
# `pom.xml`, `setup.py`, `Cargo.toml`, `pubspec.yaml` live in extractor
# families that have to be opted into. Without this list, projects that ship
# only a manifest (no committed lockfile) produce `no_sources` and the
# dependency-prompt has zero deterministic ground truth — the model falls
# back to training-data knowledge alone.
#
# `--experimental-plugins` is additive on top of the default presets (it does
# NOT replace them unless paired with `--experimental-no-default-plugins`),
# so adding entries here only ever expands coverage.
#
# When bumping `_OSV_SCANNER_VERSION`, re-verify each name still resolves —
# osv-scanner errors with `not an exact name for a plugin: "X"` if a name is
# renamed; the mocked-subprocess argv assertions in the test suite catch
# that immediately.
_MANIFEST_PLUGINS: tuple[str, ...] = (
    "dotnet/csproj",          # *.csproj / *.fsproj / *.vbproj PackageReference
    "dotnet/packagesconfig",  # legacy packages.config
    "dotnet/nugetcpm",        # Directory.Packages.props (Central Package Mgmt)
    "java/pomxml",            # bare pom.xml (no dependencyManagement resolve)
    "python/setup",           # setup.py
    "rust/cargotoml",         # Cargo.toml without Cargo.lock
    "dart/pubspec",           # pubspec.yaml without pubspec.lock
)


# --- Cache locations & policies ----------------------------------------------
# Cache lives in a gitignored sibling of `scanner/` (next to `.env`,
# `opencode.json`, etc.) — same pattern as `.ruff_cache/`, `.mypy_cache/`.
# Keeps the binary + DB version-correlated with the scanner source the
# user is running, and avoids the surprise of a 1.7 GB download landing
# in `~/.cache/` they didn't know about.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CACHE_ROOT = _REPO_ROOT / ".security-scan-cache"
_DEFAULT_BIN_DIR = _DEFAULT_CACHE_ROOT / "bin"
_DEFAULT_DB_DIR = _DEFAULT_CACHE_ROOT / "osv"

# A DB older than this is treated as effectively unavailable. 7 days is the
# point where missed-CVE recall starts to hurt enough that we'd rather
# stamp the report than silently use stale ground truth.
_DB_STALE_HOURS = 24 * 7

# osv-scanner subprocess timeouts. Scan should be quick (manifest count, not
# file count); refresh can take a few minutes on first download.
_SCAN_TIMEOUT_S = 120
_REFRESH_TIMEOUT_S = 1800

_REFRESH_SENTINEL = ".last_refresh"

_LOG_PREFIX = "[SCA]"


# --- Per-call chatlog (parallel to opencode's chatlog dir) -------------------
_chatlog_dir: Path | None = None
_chatlog_lock = threading.Lock()


def set_chatlog_dir(path: Path | None) -> None:
    """Configure where SCA subprocess outputs are persisted. Mirrors
    opencode_client.set_chatlog_dir; called from cli.scan_project."""
    global _chatlog_dir
    _chatlog_dir = path
    if path is not None:
        path.mkdir(parents=True, exist_ok=True)


def _write_chatlog(name: str, command: list[str], stdout: str, stderr: str,
                   returncode: int | None, elapsed: float) -> None:
    if _chatlog_dir is None:
        return
    rc_str = "timeout" if returncode is None else str(returncode)
    body = (
        f"# sca={name} cmd={' '.join(command)} rc={rc_str} elapsed={elapsed:.1f}s\n"
        f"\n=== STDOUT ===\n{stdout}\n"
        f"\n=== STDERR ===\n{stderr}\n"
    )
    fname = f"sca_{name}_{int(time.time() * 1000)}_{threading.get_ident()}.log"
    try:
        with _chatlog_lock:
            (_chatlog_dir / fname).write_text(body, encoding="utf-8")
    except OSError:
        # Logging must never break the scan.
        pass


# --- DB state ----------------------------------------------------------------
@dataclass
class ScaState:
    """State of the local OSV DB. Used both for first-run nudging and the
    `metadata.sca` block in the report."""
    available: bool
    db_age_hours: int | None
    stale: bool
    missing: bool
    path: str

    def as_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "db_age_hours": self.db_age_hours,
            "stale": self.stale,
            "missing": self.missing,
            "path": self.path,
        }


def db_state(db_dir: Path | None = None) -> ScaState:
    """Inspect the OSV DB cache. `available` means present and fresh enough
    to use; `stale` means present but older than _DB_STALE_HOURS."""
    db_dir = db_dir or _DEFAULT_DB_DIR
    sentinel = db_dir / _REFRESH_SENTINEL

    # No directory at all — first-run state.
    if not db_dir.is_dir():
        return ScaState(available=False, db_age_hours=None, stale=False,
                        missing=True, path=str(db_dir))

    # Directory exists but no refresh sentinel — partial / uninitialised.
    if not sentinel.is_file():
        return ScaState(available=False, db_age_hours=None, stale=False,
                        missing=True, path=str(db_dir))

    age_hours = int((time.time() - sentinel.stat().st_mtime) / 3600)
    stale = age_hours > _DB_STALE_HOURS
    return ScaState(available=not stale, db_age_hours=age_hours, stale=stale,
                    missing=False, path=str(db_dir))


# --- Binary management -------------------------------------------------------
def _detect_platform() -> tuple[str, str] | None:
    """Map host (system, machine) to one of our supported (os, arch) tuples
    or None if the host isn't supported by the bundled checksum table."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch_map = {
        "x86_64": "amd64", "amd64": "amd64",
        "arm64":  "arm64", "aarch64": "arm64",
    }
    arch = arch_map.get(machine)
    if arch is None or system not in {"darwin", "linux", "windows"}:
        return None
    key = (system, arch)
    if key not in _OSV_SCANNER_SHA256:
        return None
    return key


def _release_url(os_name: str, arch: str) -> str:
    ext = ".exe" if os_name == "windows" else ""
    return _RELEASE_URL_TEMPLATE.format(
        version=_OSV_SCANNER_VERSION, os=os_name, arch=arch, ext=ext,
    )


def _binary_filename() -> str:
    suffix = ".exe" if platform.system().lower() == "windows" else ""
    return f"osv-scanner-v{_OSV_SCANNER_VERSION}{suffix}"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _log(message: str) -> None:
    print(f"{_LOG_PREFIX} {message}", flush=True)


def ensure_osv_scanner(bin_dir: Path | None = None) -> Path | None:
    """Return a usable osv-scanner binary path, downloading the pinned
    release on first call. Returns None on any failure (caller falls
    through to stamped-degrade)."""
    override = os.environ.get("SCAN_OSV_SCANNER_BIN", "").strip()
    if override:
        candidate = Path(override).expanduser().resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            _log(f"using user-provided binary at {candidate} (SCAN_OSV_SCANNER_BIN)")
            return candidate
        _log(f"SCAN_OSV_SCANNER_BIN={override} is not an executable file; ignoring.")
        return None

    bin_dir = bin_dir or _DEFAULT_BIN_DIR
    target = bin_dir / _binary_filename()
    if target.is_file() and os.access(target, os.X_OK):
        return target

    _log(f"osv-scanner v{_OSV_SCANNER_VERSION} not cached at {target}")
    detected = _detect_platform()
    if detected is None:
        _log(f"unsupported host platform: {platform.system()}/{platform.machine()}; "
             "set SCAN_OSV_SCANNER_BIN to a pre-installed binary.")
        return None
    os_name, arch = detected
    _log(f"detected host platform: {os_name}/{arch}")

    expected_sha = _OSV_SCANNER_SHA256[(os_name, arch)]
    url = _release_url(os_name, arch)
    _log(f"downloading {url}")

    bin_dir.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".partial")
    try:
        with urllib.request.urlopen(url, timeout=_REFRESH_TIMEOUT_S) as response:
            with partial.open("wb") as fh:
                shutil.copyfileobj(response, fh)
    except (urllib.error.URLError, OSError) as exc:
        _log(f"download failed: {exc}")
        partial.unlink(missing_ok=True)
        return None

    actual_sha = _sha256_file(partial)
    if actual_sha != expected_sha:
        _log(f"sha256 mismatch — expected {expected_sha}, got {actual_sha}. "
             "Refusing to install. Pinned version may be stale; bump "
             "_OSV_SCANNER_VERSION in scanner/sca.py.")
        partial.unlink(missing_ok=True)
        return None
    _log(f"sha256 verified: {actual_sha}")

    partial.replace(target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    _log(f"cached binary at {target}")
    return target


# --- Scan invocation ---------------------------------------------------------
@dataclass
class ScaRunResult:
    """Outcome of a Phase 1 SCA invocation."""
    json_text: str  # pretty-printed osv-scanner JSON; "" when no usable result
    metadata: dict[str, object] = field(default_factory=dict)


def _paths_to_ignore_args(project_dir: Path, exclude_dirs: list[str]) -> list[str]:
    """Translate a list of directory basenames into osv-scanner
    `--experimental-exclude` arguments so SCA sees the same effective tree
    the LLM does. project_dir is unused (kept in the signature for callers
    that may want to pin globs in the future); osv-scanner v2 takes a bare
    dirname / glob / regex spec."""
    del project_dir
    args: list[str] = []
    for name in sorted({n.strip() for n in exclude_dirs if n and n.strip()}):
        args.extend(["--experimental-exclude", name])
    return args


def _normalise_paths(payload: object, project_dir: Path) -> object:
    """Walk osv-scanner JSON and rewrite any absolute path under
    project_dir to a relative one, so paths in SCA output line up with
    paths in {{FILE_LISTING}} / {{MANIFEST_CONTENTS}}."""
    project_str = str(project_dir).rstrip("/")
    project_with_sep = project_str + os.sep

    def _rewrite(value: object) -> object:
        if isinstance(value, dict):
            return {k: _rewrite(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_rewrite(v) for v in value]
        if isinstance(value, str):
            if value == project_str:
                return "."
            if value.startswith(project_with_sep):
                return value[len(project_with_sep):]
        return value

    return _rewrite(payload)


def run_osv_scan(project_dir: Path, bin_path: Path, db_dir: Path,
                 exclude_dirs: list[str]) -> ScaRunResult:
    """Run osv-scanner offline against project_dir and return a pretty-printed
    JSON blob plus metadata for the report. On any failure returns an empty
    result; the caller stamps the report with the reason."""
    cmd = [
        str(bin_path),
        "scan", "source",
        "--recursive",
        # Disable osv-scanner's default `.gitignore` filtering. Our use case
        # is "scan whatever the user pointed us at"; gitignore filtering is
        # actively hostile because (a) users routinely point us at projects
        # living inside our own gitignored `input/` directory, where every
        # subpath inherits an `input/*` ignore from the security-scan repo
        # itself, and (b) project-local `.gitignore`s from third-party
        # repos can hide manifests we want to scan. The `_paths_to_ignore_args`
        # list (passed via `--experimental-exclude` below) is the explicit
        # exclusion mechanism we control and want osv-scanner to respect.
        "--no-ignore",
        "--offline-vulnerabilities",
        "--local-db-path", str(db_dir),
        "--format", "json",
        *(arg for plugin in _MANIFEST_PLUGINS
              for arg in ("--experimental-plugins", plugin)),
        *_paths_to_ignore_args(project_dir, exclude_dirs),
        str(project_dir),
    ]

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_SCAN_TIMEOUT_S,
        )
    except FileNotFoundError as exc:
        elapsed = time.monotonic() - start
        _log(f"osv-scanner binary disappeared between checks: {exc}")
        _write_chatlog("scan", cmd, "", str(exc), None, elapsed)
        return ScaRunResult(json_text="", metadata={"runtime_s": elapsed,
                                                    "error": "binary_missing"})
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        partial_stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        partial_stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        _log(f"osv-scanner timed out after {_SCAN_TIMEOUT_S}s")
        _write_chatlog("scan", cmd, partial_stdout, partial_stderr, None, elapsed)
        return ScaRunResult(json_text="", metadata={"runtime_s": elapsed,
                                                    "error": "timeout"})

    elapsed = time.monotonic() - start
    _write_chatlog("scan", cmd, result.stdout or "", result.stderr or "",
                   result.returncode, elapsed)

    # osv-scanner exit codes:
    #   0   — scan succeeded, no advisory matches
    #   1   — scan succeeded, advisory matches found
    #   128 — nothing scannable (no recognised manifests in the tree)
    # Anything else is a real failure.
    stderr_text = (result.stderr or "")
    no_sources = (
        result.returncode == 128
        or "no package sources found" in stderr_text.lower()
    )
    if no_sources:
        # Genuinely unscannable project (pure scripts, custom build system,
        # ecosystems osv-scanner doesn't extract for). Not a degraded scan —
        # just nothing for the SCA tool to do. Surface this distinctly so the
        # report doesn't tell triagers "SCA failed" when it didn't.
        _log(f"osv-scanner v{_OSV_SCANNER_VERSION} → no package manifests "
             f"recognised in project (runtime: {elapsed:.1f}s); "
             "Phase 1 will rely on model knowledge.")
        return ScaRunResult(json_text="", metadata={
            "runtime_s": round(elapsed, 2),
            "osv_scanner_version": _OSV_SCANNER_VERSION,
            "advisory_match_count": 0,
            "no_sources": True,
        })
    if result.returncode not in (0, 1):
        stderr_tail = stderr_text.strip().splitlines()[-3:]
        _log(f"osv-scanner exited {result.returncode}: "
             f"{' | '.join(stderr_tail) or '(no stderr)'}")
        return ScaRunResult(json_text="", metadata={
            "runtime_s": elapsed, "error": "nonzero_exit",
            "returncode": result.returncode,
        })

    try:
        payload = json.loads(result.stdout or "")
    except json.JSONDecodeError as exc:
        _log(f"could not parse osv-scanner JSON output: {exc}")
        return ScaRunResult(json_text="", metadata={
            "runtime_s": elapsed, "error": "parse_failure",
        })

    payload = _normalise_paths(payload, project_dir)
    match_count, advisories = _extract_advisories(payload)
    state = db_state(db_dir)
    age = state.db_age_hours if state.db_age_hours is not None else 0
    _log(f"osv-scanner v{_OSV_SCANNER_VERSION} → {match_count} advisory match(es) "
         f"(db age: {age}h, runtime: {elapsed:.1f}s)")

    return ScaRunResult(
        json_text=json.dumps(payload, indent=2, sort_keys=True),
        metadata={
            "osv_scanner_version": _OSV_SCANNER_VERSION,
            "advisory_match_count": match_count,
            # Per-(package, version, advisory-id) tuples so the report writer
            # can build a citation-recall delta against the rendered findings.
            # Each entry: {"package": str, "version": str, "ecosystem": str,
            # "id": str, "aliases": [str], "summary": str}.
            "advisories": advisories,
            "runtime_s": round(elapsed, 2),
        },
    )


def _count_advisory_matches(payload: object) -> int:
    """Backwards-compatible wrapper used by tests; counts advisory matches
    in an osv-scanner JSON payload."""
    count, _ = _extract_advisories(payload)
    return count


def _advisory_severity(vuln: dict[str, object]) -> str:
    """Best-effort one-of {CRITICAL,HIGH,MEDIUM,LOW,INFO,""} for an
    osv-scanner vulnerability entry. Tries `database_specific.severity`
    first (canonical string from the source feed), falls back to the
    highest CVSS base score in the `severity[]` list, bucketed via the
    standard CVSS v3 ranges (≥9 critical, ≥7 high, ≥4 medium, >0 low).
    Returns "" when neither shape carries usable data."""
    db_specific = vuln.get("database_specific")
    if isinstance(db_specific, dict):
        canon = str(db_specific.get("severity", "") or "").strip().upper()
        if canon in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW", "INFO"}:
            return "MEDIUM" if canon == "MODERATE" else canon

    sev_list = vuln.get("severity")
    if isinstance(sev_list, list):
        best_score = -1.0
        for entry in sev_list:
            if not isinstance(entry, dict):
                continue
            score = _cvss_base_score(str(entry.get("score", "") or ""))
            if score is not None and score > best_score:
                best_score = score
        if best_score >= 9.0:
            return "CRITICAL"
        if best_score >= 7.0:
            return "HIGH"
        if best_score >= 4.0:
            return "MEDIUM"
        if best_score > 0.0:
            return "LOW"
    return ""


def _cvss_base_score(vector: str) -> float | None:
    """Pull the base score out of a CVSS vector string. osv-scanner stores
    the raw vector (e.g. `CVSS:3.1/AV:N/AC:L/.../A:H`); a few feeds embed
    a score prefix (`9.8/CVSS:3.1/...`). Returns None if no numeric score
    can be recovered. Pure CVSS-vector parsing is out of scope; we only
    handle the score-prefix shape osv-scanner has been observed to emit."""
    if not vector:
        return None
    head = vector.split("/", 1)[0]
    try:
        score = float(head)
    except ValueError:
        return None
    if 0.0 <= score <= 10.0:
        return score
    return None


def _extract_advisories(payload: object) -> tuple[int, list[dict[str, object]]]:
    """Walk an osv-scanner JSON payload and pull out every advisory match
    along with the package / version / ecosystem context. Returns
    `(count, advisories)` where `advisories` is a list of dicts the
    report writer can compare against finding-text citations."""
    advisories: list[dict[str, object]] = []

    def walk(value: object, package: dict[str, object] | None) -> None:
        if isinstance(value, dict):
            pkg_dict = value.get("package")
            if isinstance(pkg_dict, dict):
                package = pkg_dict
            vulns = value.get("vulnerabilities")
            if isinstance(vulns, list) and isinstance(package, dict):
                pkg_name = str(package.get("name", "") or "")
                pkg_ver = str(package.get("version", "") or "")
                pkg_eco = str(package.get("ecosystem", "") or "")
                for v in vulns:
                    if not isinstance(v, dict):
                        continue
                    advisory_id = str(v.get("id", "") or "")
                    if not advisory_id:
                        continue
                    raw_aliases = v.get("aliases") or []
                    aliases = [str(a) for a in raw_aliases
                               if isinstance(a, (str, int))]
                    advisories.append({
                        "package": pkg_name,
                        "version": pkg_ver,
                        "ecosystem": pkg_eco,
                        "id": advisory_id,
                        "aliases": aliases,
                        "summary": str(v.get("summary", "") or "")[:200],
                        "severity": _advisory_severity(v),
                    })
            for v in value.values():
                walk(v, package)
        elif isinstance(value, list):
            for item in value:
                walk(item, package)

    walk(payload, None)
    return len(advisories), advisories


# --- Refresh -----------------------------------------------------------------
# osv-scanner --download-offline-databases pulls every ecosystem it indexes
# (npm, PyPI, Maven, NuGet, Go, RubyGems, crates.io, Packagist, Hex, Pub,
# ConanCenter, GitHub Actions, plus Linux distro feeds: AlmaLinux, Alpine,
# Debian, Rocky, Ubuntu, etc.). We don't filter — the plan trades disk
# (~1.5–2 GB) for "works for any stack without detection logic".


def refresh_offline_db(db_dir: Path | None = None,
                       bin_dir: Path | None = None) -> int:
    """Refresh the local OSV DB across every ecosystem osv-scanner supports.
    Returns 0 on success, 1 on any failure (cron-friendly).
    """
    db_dir = db_dir or _DEFAULT_DB_DIR
    bin_path = ensure_osv_scanner(bin_dir)
    if bin_path is None:
        _log("refresh aborted: osv-scanner binary is not available.")
        return 1

    db_dir.mkdir(parents=True, exist_ok=True)
    _log(f"refreshing all OSV ecosystems into {db_dir} "
         "(~1.5–2 GB on disk; initial pull may take a few minutes).")

    # osv-scanner --download-offline-databases pulls only the DBs for
    # ecosystems whose lockfiles it detected in the scan source. To prime
    # the cache for every ecosystem we care about, synthesise one minimal
    # but extractable lockfile per ecosystem in a tempdir. Each stub names
    # one trivially-pinned package so osv-scanner's extractor produces a
    # PURL → triggers the ecosystem DB download. The scan produces no
    # findings (these are not real vulnerable versions); we only care
    # about the side-effect.
    stub_dir = Path(tempfile.mkdtemp(prefix="osv-refresh-stub-"))
    _write_ecosystem_stubs(stub_dir)

    cmd = [
        str(bin_path),
        "scan", "source",
        "--offline-vulnerabilities",
        "--download-offline-databases",
        "--local-db-path", str(db_dir),
        "--format", "json",
        str(stub_dir),
    ]

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_REFRESH_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        partial_stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        _log(f"refresh timed out after {_REFRESH_TIMEOUT_S}s. Partial stderr tail: "
             f"{partial_stderr.strip().splitlines()[-3:]}")
        _write_chatlog("refresh", cmd, "", partial_stderr, None, elapsed)
        return 1
    except FileNotFoundError as exc:
        _log(f"osv-scanner binary disappeared during refresh: {exc}")
        return 1
    finally:
        shutil.rmtree(stub_dir, ignore_errors=True)

    elapsed = time.monotonic() - start
    _write_chatlog("refresh", cmd, result.stdout or "", result.stderr or "",
                   result.returncode, elapsed)

    if result.returncode not in (0, 1):
        stderr_tail = (result.stderr or "").strip().splitlines()[-5:]
        _log(f"refresh exited {result.returncode}: "
             f"{' | '.join(stderr_tail) or '(no stderr)'}")
        return 1

    sentinel = db_dir / _REFRESH_SENTINEL
    sentinel.touch()
    size_bytes = _dir_size(db_dir)
    eco_count = _count_ecosystems(db_dir)
    _log(f"OSV DB ready at {db_dir} "
         f"({_humansize(size_bytes)} across {eco_count} ecosystem(s))")
    if elapsed:
        _log(f"refresh completed in {elapsed:.1f}s")
    return 0


def _count_ecosystems(db_dir: Path) -> int:
    """Count ecosystem subdirectories under the OSV cache. osv-scanner v2
    nests them under db_dir/osv-scanner/<Ecosystem>/. Falls back to direct
    children for forward-compat with potential schema changes."""
    nested = db_dir / "osv-scanner"
    base = nested if nested.is_dir() else db_dir
    return sum(1 for child in base.iterdir() if child.is_dir())


def _dir_size(path: Path) -> int:
    total = 0
    for entry in path.rglob("*"):
        try:
            if entry.is_file():
                total += entry.stat().st_size
        except OSError:
            continue
    return total


def _write_ecosystem_stubs(stub_dir: Path) -> None:
    """Create a minimal lockfile per ecosystem so osv-scanner's
    --download-offline-databases pulls the matching DB.

    Each stub names one trivially-pinned package; we don't care whether
    the version actually exists upstream — the extractor only needs to
    produce a PURL to trigger the ecosystem download.
    """
    stubs: dict[str, str] = {
        # npm
        "package-lock.json": json.dumps({
            "name": "stub", "version": "0.0.0", "lockfileVersion": 3,
            "packages": {"": {"name": "stub", "version": "0.0.0"},
                         "node_modules/left-pad": {"version": "0.0.1"}},
        }),
        # PyPI
        "requirements.txt": "requests==2.0.0\n",
        # Go modules — a real require line triggers extraction.
        "go.mod": "module stub\n\ngo 1.21\n\nrequire github.com/stretchr/testify v1.0.0\n",
        # Maven
        "pom.xml": (
            '<?xml version="1.0"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            '  <modelVersion>4.0.0</modelVersion>\n'
            '  <groupId>stub</groupId><artifactId>stub</artifactId><version>0.0.0</version>\n'
            '  <dependencies><dependency>\n'
            '    <groupId>org.apache.commons</groupId>\n'
            '    <artifactId>commons-lang3</artifactId><version>3.0</version>\n'
            '  </dependency></dependencies>\n'
            '</project>\n'
        ),
        # NuGet (PackageReference style under packages.lock.json)
        "packages.lock.json": json.dumps({
            "version": 1,
            "dependencies": {"net6.0": {"Newtonsoft.Json": {
                "type": "Direct", "requested": "[12.0.0, )",
                "resolved": "12.0.0", "contentHash": "stub",
            }}},
        }),
        # RubyGems
        "Gemfile.lock": (
            "GEM\n  remote: https://rubygems.org/\n  specs:\n"
            "    rake (10.0.0)\n\nDEPENDENCIES\n  rake\n\nBUNDLED WITH\n   2.0.0\n"
        ),
        # crates.io
        "Cargo.lock": (
            'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        ),
        # Packagist (Composer)
        "composer.lock": json.dumps({
            "_readme": ["stub"], "content-hash": "0",
            "packages": [{"name": "monolog/monolog", "version": "1.0.0"}],
            "packages-dev": [], "platform": [], "platform-dev": [],
            "aliases": [], "minimum-stability": "stable",
            "stability-flags": [], "prefer-stable": False,
            "prefer-lowest": False,
        }),
        # Hex (Elixir)
        "mix.lock": '%{"jason": {:hex, :jason, "1.0.0"}}\n',
        # Pub (Dart)
        "pubspec.lock": (
            "packages:\n  http:\n    dependency: direct main\n"
            "    description: {name: http, url: https://pub.dev}\n"
            "    source: hosted\n    version: \"0.1.0\"\nsdks:\n  dart: \">=2.0.0 <4.0.0\"\n"
        ),
    }
    for name, content in stubs.items():
        (stub_dir / name).write_text(content, encoding="utf-8")


def _humansize(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


# Documented public API. Importable from `scanner.sca`.
__all__ = [
    "ScaState",
    "ScaRunResult",
    "db_state",
    "ensure_osv_scanner",
    "refresh_offline_db",
    "run_osv_scan",
    "set_chatlog_dir",
]
