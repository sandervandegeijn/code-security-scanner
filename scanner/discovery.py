"""Project file discovery — pure filesystem walk, no LLM calls.

Two variants:
  - `discover_all_files`: every file (used by Phase 0/1 to build the
    directory tree and find manifests).
  - `discover_files`: filtered by extension/exclude lists (the actual
    Phase 2 work-list).

Called once per scan from `cli.scan_project` before any opencode call.
"""

import os
from pathlib import Path

from .config import INCLUDE_NO_EXT


def discover_all_files(root: str, exclude_dirs: set[str]) -> list[Path]:
    """Every file under `root` (sorted), minus excluded directories."""
    files: list[Path] = []
    root_path = Path(root).resolve()
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_file():
                files.append(fpath)
    files.sort()
    return files


def discover_files(
    root: str,
    extensions: set[str],
    exclude_dirs: set[str],
    exclude_files: set[str],
) -> list[Path]:
    """Source files for Phase 2 review: filtered by extension and exclude lists."""
    files: list[Path] = []
    root_path = Path(root).resolve()
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in filenames:
            if fname in exclude_files:
                continue
            fpath = Path(dirpath) / fname
            if not fpath.is_file():
                continue
            ext = fpath.suffix.lower()
            if ext in extensions or fname in INCLUDE_NO_EXT:
                files.append(fpath)
    files.sort()
    return files
