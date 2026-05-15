"""Prompt template loading, manifest bundling, and per-prompt builders.

All functions here are pure (no LLM calls). Each `build_*_prompt` is
called by the matching phase: `build_discovery_prompt` (Phase 0),
`build_dependency_prompt` (Phase 1), `build_file_prompt` (Phase 2 via
`perfile`), `build_confirmation_prompt` (`confirmation`). The dedup
template is interpolated inline in `dedup._dedup_file_group`.

Order of placeholders in every cache-stable prompt:

    [template] [PROJECT_BRIEF] [DIRECTORY_TREE] [DEVELOPER_FEEDBACK]
    ... then variable parts (FILENAME / FINDING_JSON / FINDINGS_JSON).

Everything before the variable block is identical across calls in a
project, which is what Azure's prefix cache keys on. Don't reorder.
"""

import json
from pathlib import Path


def load_template(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def build_discovery_prompt(template: str, all_files: list[Path],
                           project_dir: Path,
                           project_docs_text: str = "") -> str:
    """Phase 0 prompt: project root, project docs, file listing, manifest contents."""
    file_listing = "\n".join(
        str(f.relative_to(project_dir)) for f in all_files
    )
    manifest_contents = collect_manifest_contents(all_files, project_dir)
    return (
        template
        .replace("{{PROJECT_ROOT}}", str(project_dir))
        .replace("{{PROJECT_DOCS}}", project_docs_text or "(none)")
        .replace("{{FILE_LISTING}}", file_listing)
        .replace("{{MANIFEST_CONTENTS}}", manifest_contents)
    )


def build_dependency_prompt(template: str, all_files: list[Path],
                            project_dir: Path, feedback_text: str = "",
                            sca_results: str = "") -> str:
    """Phase 1 prompt: file listing + manifest contents + developer feedback +
    osv-scanner ground-truth CVE data (empty when SCA is unavailable; the
    prompt template instructs the LLM how to handle that)."""
    file_listing = "\n".join(
        str(f.relative_to(project_dir)) for f in all_files
    )
    manifest_contents = collect_manifest_contents(all_files, project_dir)
    return (
        template
        .replace("{{PROJECT_ROOT}}", str(project_dir))
        .replace("{{FILE_LISTING}}", file_listing)
        .replace("{{MANIFEST_CONTENTS}}", manifest_contents)
        .replace("{{DEVELOPER_FEEDBACK}}", feedback_text or "(none)")
        .replace("{{SCA_RESULTS}}", sca_results or "(none — osv-scanner unavailable; see scanner log)")
    )


_MANIFEST_PER_FILE_CAP = 150_000  # bytes per file; truncated above this


def _is_manifest(name: str, ext: str) -> bool:
    manifest_names = {
        "gemfile", "pipfile", "go.mod", "go.sum",
        "cargo.toml", "cargo.lock", "build.gradle",
        "build.gradle.kts", "pom.xml", "makefile",
        "dockerfile", "docker-compose.yml", "docker-compose.yaml",
        ".dockerignore",
        # Python
        "requirements.txt", "constraints.txt", "setup.py", "setup.cfg",
        "pipfile.lock",
        # .NET / NuGet
        "nuget.config", "global.json",
        "directory.build.props", "directory.build.targets",
        "directory.packages.props",
    }
    manifest_exts = {
        ".config", ".xml", ".json", ".yaml", ".yml", ".toml",
        ".cfg", ".ini", ".props", ".targets", ".lock",
    }
    if ext in manifest_exts or name in manifest_names:
        return True
    # Python pattern: requirements-<something>.txt, requirements_<something>.txt
    if (name.startswith("requirements-") or name.startswith("requirements_")) and name.endswith(".txt"):
        return True
    if name.endswith((".csproj", ".fsproj", ".vbproj", ".sln")):
        return True
    return False


def collect_manifest_contents(all_files: list[Path], project_dir: Path) -> str:
    """Bundle every detected dependency manifest into one labelled blob.
    Per-file content is soft-truncated at _MANIFEST_PER_FILE_CAP."""
    blocks: list[str] = []
    for fpath in all_files:
        try:
            size = fpath.stat().st_size
            if size == 0:
                continue
            name = fpath.name.lower()
            ext = fpath.suffix.lower()
            if not _is_manifest(name, ext):
                continue
            content = fpath.read_text(encoding="utf-8", errors="replace")
            if len(content) > _MANIFEST_PER_FILE_CAP:
                head = content[:_MANIFEST_PER_FILE_CAP]
                content = (
                    f"{head}\n\n"
                    f"[... truncated; original size {size:,} bytes, "
                    f"showing first {_MANIFEST_PER_FILE_CAP:,}]"
                )
            rel = fpath.relative_to(project_dir)
            blocks.append(f"=== {rel} ===\n{content}")
        except (OSError, ValueError):
            continue
    return "\n\n".join(blocks) if blocks else "(no candidate files found)"


_TREE_CHAR_CAP = 40_000  # ~10k tokens; soft cap to protect context


def build_directory_tree(all_files: list[Path], project_dir: Path) -> str:
    """Render a compact project-relative layout of scanned files.

    Groups files by directory (one header per directory) so shared prefixes
    are not repeated on every line. Order is lexicographic by POSIX path so
    output is deterministic across runs — stable bytes are what the LLM
    provider's prefix cache keys on.

    Truncates at _TREE_CHAR_CAP chars with a marker so the model knows the
    list is incomplete on very large projects.
    """
    by_dir: dict[str, list[str]] = {}
    for f in all_files:
        try:
            rel = f.relative_to(project_dir).as_posix()
        except ValueError:
            continue
        if "/" in rel:
            parent, name = rel.rsplit("/", 1)
        else:
            parent, name = "", rel
        by_dir.setdefault(parent, []).append(name)

    lines: list[str] = []
    for parent in sorted(by_dir.keys()):
        header = f"{parent}/" if parent else "./"
        lines.append(header)
        for name in sorted(by_dir[parent]):
            lines.append(f"  {name}")

    rendered = "\n".join(lines)
    if len(rendered) <= _TREE_CHAR_CAP:
        return rendered

    head = rendered[:_TREE_CHAR_CAP]
    # Cut at the last newline so we don't split a filename mid-line.
    cut = head.rfind("\n")
    if cut > 0:
        head = head[:cut]
    shown_files = sum(1 for ln in head.split("\n") if ln.startswith("  "))
    omitted = len(all_files) - shown_files
    return f"{head}\n[... {omitted} more files omitted; see discovery file listing]"


_FEEDBACK_CHAR_CAP = 40_000  # ~10k tokens; soft cap to protect context

_PROJECT_DOCS_CHAR_CAP = 40_000  # separate budget from developer feedback

# Top-level docs auto-loaded for Phase 0 discovery context. Matched
# case-insensitively on basename. Order here is the order they're
# rendered in the prompt — README first so the model anchors on the
# project's own elevator pitch before the more specialised docs.
_PROJECT_DOC_CANDIDATES = (
    "README.md",
    "SECURITY.md",
    "ARCHITECTURE.md",
    "CONTRIBUTING.md",
)


def load_project_docs(project_dir: Path) -> str:
    """Bundle the project's own top-level docs for Phase 0 context.

    Reads `README.md`, `SECURITY.md`, `ARCHITECTURE.md`,
    `CONTRIBUTING.md` at the project root (case-insensitive) plus any
    `*.md` directly inside `docs/` (non-recursive). Missing or empty
    files are skipped silently. Total bundle is soft-capped at
    `_PROJECT_DOCS_CHAR_CAP` with a truncation marker so an oversized
    monorepo README can't blow the context budget.

    Returns "" when no candidate docs are found.
    """
    if not project_dir.is_dir():
        return ""

    seen: set[Path] = set()
    picked: list[Path] = []

    # Build a case-insensitive index of root entries so we match
    # `readme.md`, `Readme.md`, etc.
    root_index: dict[str, Path] = {}
    try:
        for entry in project_dir.iterdir():
            if entry.is_file():
                root_index[entry.name.lower()] = entry
    except OSError:
        return ""

    for name in _PROJECT_DOC_CANDIDATES:
        match = root_index.get(name.lower())
        if match is not None and match not in seen:
            picked.append(match)
            seen.add(match)

    docs_dir = project_dir / "docs"
    if docs_dir.is_dir():
        try:
            doc_files = sorted(
                p for p in docs_dir.iterdir()
                if p.is_file() and p.suffix.lower() == ".md"
            )
        except OSError:
            doc_files = []
        for p in doc_files:
            if p not in seen:
                picked.append(p)
                seen.add(p)

    blocks: list[str] = []
    for path in picked:
        try:
            content = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not content:
            continue
        try:
            rel = path.relative_to(project_dir).as_posix()
        except ValueError:
            rel = path.name
        blocks.append(f"=== {rel} ===\n{content}")

    if not blocks:
        return ""

    rendered = "\n\n".join(blocks)
    if len(rendered) <= _PROJECT_DOCS_CHAR_CAP:
        return rendered
    head = rendered[:_PROJECT_DOCS_CHAR_CAP]
    cut = head.rfind("\n")
    if cut > 0:
        head = head[:cut]
    return (
        f"{head}\n\n[... truncated; total project docs exceeded "
        f"{_PROJECT_DOCS_CHAR_CAP:,} chars]"
    )


def load_developer_feedback(feedback_file: Path) -> str:
    """Load a single SECURITY_SCAN.md file for prompt injection.

    Returns "" when the file is missing, unreadable, or empty. Truncates
    above _FEEDBACK_CHAR_CAP so an oversized note can't blow the context
    budget.
    """
    if not feedback_file.is_file():
        return ""
    try:
        content = feedback_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    if not content:
        return ""

    rendered = f"=== {feedback_file.name} ===\n{content}"
    if len(rendered) <= _FEEDBACK_CHAR_CAP:
        return rendered
    head = rendered[:_FEEDBACK_CHAR_CAP]
    cut = head.rfind("\n")
    if cut > 0:
        head = head[:cut]
    return f"{head}\n\n[... truncated; total feedback exceeded {_FEEDBACK_CHAR_CAP:,} chars]"


def build_file_prompt(template: str, brief_text: str, tree_text: str,
                      feedback_text: str, filepath: Path,
                      project_dir: Path) -> str:
    """Phase 2 per-file prompt; placeholder order is cache-stable (see module docstring)."""
    content = filepath.read_text(encoding="utf-8", errors="replace")
    rel = str(filepath.relative_to(project_dir))
    return (
        template
        .replace("{{PROJECT_BRIEF}}", brief_text)
        .replace("{{DIRECTORY_TREE}}", tree_text)
        .replace("{{DEVELOPER_FEEDBACK}}", feedback_text or "(none)")
        .replace("{{FILENAME}}", rel)
        .replace("{{FILE_CONTENT}}", content)
    )


def build_confirmation_prompt(template: str, brief_text: str, tree_text: str,
                              feedback_text: str, finding: dict) -> str:
    """Confirmation-pass prompt: same cache-stable prefix + the single finding JSON."""
    return (
        template
        .replace("{{PROJECT_BRIEF}}", brief_text)
        .replace("{{DIRECTORY_TREE}}", tree_text)
        .replace("{{DEVELOPER_FEEDBACK}}", feedback_text or "(none)")
        .replace("{{FINDING_JSON}}", json.dumps(finding, indent=2))
    )
