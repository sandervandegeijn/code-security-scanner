"""Finding schema, normalization, and synthetic parse-failure findings.

A "finding" is a plain dict (no class) with the fields documented in
CLAUDE.md. Every phase that produces findings (`perfile`, the dependency
audit in `cli`, `confirmation`) routes raw LLM output through
`parse_findings_array` to coerce shapes and drop garbage. When the JSON
extractor fails, `parse_failure_finding` injects a sentinel so a bad
file is visible in the report instead of silently dropped.
"""

from .config import SEVERITY_ORDER


REQUIRED_FINDING_FIELDS = [
    "severity", "title", "file", "line", "category",
    "description", "evidence", "recommendation", "test_steps",
    "mitigations_considered",
]


def normalize_finding(raw: dict, phase: str, default_file: str = "") -> dict | None:
    if not isinstance(raw, dict):
        return None
    out: dict = {"phase": phase}
    for f in REQUIRED_FINDING_FIELDS:
        val = raw.get(f, "")
        out[f] = "" if val is None else str(val).strip()
    # dependency findings carry an extra field
    out["dependency"] = str(raw.get("dependency", "") or "").strip()
    if out["severity"] not in SEVERITY_ORDER:
        return None
    if not out["title"]:
        return None
    if not out["file"]:
        out["file"] = default_file
    # populated later
    out["confidence"] = ""
    out["confirmation_note"] = ""
    out["dropped"] = False
    return out


def parse_findings_array(value: object, phase: str, default_file: str = "") -> list[dict]:
    if isinstance(value, list):
        items = value
    elif isinstance(value, dict) and isinstance(value.get("findings"), list):
        items = value["findings"]
    else:
        return []
    out: list[dict] = []
    for raw in items:
        norm = normalize_finding(raw, phase, default_file)
        if norm is not None:
            out.append(norm)
    return out


def parse_failure_finding(filepath: str, raw: str) -> dict:
    return {
        "phase": "Per-File Review",
        "severity": "INFO",
        "title": "SCAN_PARSE_FAILURE",
        "file": filepath,
        "line": "",
        "category": "Scanner",
        "description": (
            "The AI did not return parseable JSON for this file after one retry. "
            "Finding list for this file could not be recovered."
        ),
        "evidence": raw[-500:].strip(),
        "recommendation": "Re-run the scanner on this file in isolation.",
        "test_steps": "",
        "dependency": "",
        "confidence": "likely",
        "confirmation_note": "Synthetic finding produced by the scanner; no model verdict.",
        "dropped": False,
    }
