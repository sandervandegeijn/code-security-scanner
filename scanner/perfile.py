"""Phase 2 — per-file security review wrapper.

Single function `scan_single_file`: builds the per-file prompt, calls
opencode, normalises the JSON array, and (on parse failure) emits a
sentinel finding so the file shows up in the report. Invoked once per
source file, in parallel, by `cli.scan_project`.
"""

from pathlib import Path

from .findings import parse_failure_finding, parse_findings_array
from .opencode_client import call_opencode_json
from .prompts import build_file_prompt


def scan_single_file(filepath: Path, project_dir: Path, template: str,
                     brief_text: str, tree_text: str, feedback_text: str,
                     model: str, timeout: int) -> tuple[list[dict], str]:
    prompt = build_file_prompt(template, brief_text, tree_text, feedback_text,
                               filepath, project_dir)
    nudge = (
        "Your previous response could not be parsed as JSON. Respond with ONLY "
        "a JSON array of finding objects (or [] if none). No prose, no code fences."
    )
    value, raw = call_opencode_json(prompt, project_dir.as_posix(), model, timeout, nudge,
                                    phase="perfile")

    default_file = str(filepath.relative_to(project_dir))
    if value is None:
        return [parse_failure_finding(default_file, raw)], raw
    return parse_findings_array(value, "Per-File Review", default_file), raw
