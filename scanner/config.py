"""Defaults and ordering tables shared across the scanner.

Pure data, no behaviour. Imported by `cli`, `dedup`, `findings`,
`confirmation`, and `report`. Keep this leaf module dependency-free —
adding imports here creates cycles.
"""

DEFAULT_EXTENSIONS = {
    ".cs", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".rs", ".c",
    ".cpp", ".h", ".hpp", ".swift", ".kt",
    ".aspx", ".cshtml", ".razor", ".vue", ".svelte",
    ".html", ".htm",
    ".sql",
    ".config", ".xml", ".json", ".yaml", ".yml",
    ".ps1", ".psm1", ".sh", ".bash",
    ".tf", ".hcl",
    ".dockerfile",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "bower_components",
    "bin", "obj", "Debug", "Release",
    ".vs", ".vscode", ".idea",
    "packages", ".nuget", "__pycache__", ".tox",
    "vendor", "venv", ".venv", "env",
    "dist", "build", "out", "target",
    ".terraform",
    "TestResults", "coverage",
}

DEFAULT_EXCLUDE_FILES = {
    # Lockfiles — Phase 1 deps audit already reads these via the manifest
    # collector, so re-reading them in Phase 2 would just produce duplicate
    # dep findings against source.
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Gemfile.lock", "Pipfile.lock",
    "poetry.lock", "packages.lock.json", "Cargo.lock",
    # Package-manager manifests with extensions matching DEFAULT_EXTENSIONS
    # (.json / .xml / .yaml). Phase 1 already covers them deterministically
    # (osv-scanner) plus contextually (LLM); Phase 2 review on the same
    # files only produces overlap.
    "package.json", "composer.json", "bower.json",
    "pom.xml",
    "pubspec.yaml", "pubspec.yml",
}

INCLUDE_NO_EXT = {"Dockerfile", "Makefile"}

DEFAULT_MODEL_HEAVY = "azure/gpt-5.5"
DEFAULT_MODEL_LIGHT = "azure/gpt-5.4-mini"
# Back-compat alias for the historical single-model constant. Existing
# imports (e.g. `from .config import DEFAULT_MODEL`) keep working and
# resolve to the heavy slot.
DEFAULT_MODEL = DEFAULT_MODEL_HEAVY
DEFAULT_PARALLEL = 10

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"confirmed": 0, "likely": 1, "false_positive": 2}
