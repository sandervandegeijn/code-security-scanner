"""Final business-readable report summary generation.

Optional last step in `cli.finalize_and_report`. Sends a reduced view
of the (deduped, confirmed) findings to the LLM along with a
vulnerability-handling standard, and asks for a one-paragraph
business summary that ends up at the top of the markdown report.

The reduced payload is built by `_visible_finding_payload` and excludes
dropped findings. If the prompt or standard files are missing, the
caller falls back to a static apology string (no LLM call).
"""

import json

from .config import SEVERITY_ORDER
from .opencode_client import call_opencode_json


def _counts(findings: list[dict]) -> dict:
    visible = [f for f in findings if not f.get("dropped")]
    dropped = [f for f in findings if f.get("dropped")]
    severities = {s: 0 for s in SEVERITY_ORDER}
    confidence = {"confirmed": 0, "likely": 0}
    per_file_count = 0
    dependency_count = 0
    for f in visible:
        sev = f.get("severity", "INFO")
        severities[sev] = severities.get(sev, 0) + 1
        conf = f.get("confidence", "")
        if conf in confidence:
            confidence[conf] += 1
        if f.get("phase") == "Dependency Audit":
            dependency_count += 1
        else:
            per_file_count += 1
    return {
        "severity": severities,
        "confidence": confidence,
        "dropped": len(dropped),
        "per_file_count": per_file_count,
        "dependency_count": dependency_count,
    }


def _visible_finding_payload(findings: list[dict]) -> list[dict]:
    """Reduced finding view for the summary prompt: skips dropped findings
    and keeps only the fields the business summary needs."""
    out: list[dict] = []
    for f in findings:
        if f.get("dropped"):
            continue
        out.append({
            "phase": f.get("phase", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", ""),
            "title": f.get("title", ""),
            "category": f.get("category", ""),
            "file": f.get("file", ""),
            "line": f.get("line", ""),
            "dependency": f.get("dependency", ""),
            "description": f.get("description", ""),
            "recommendation": f.get("recommendation", ""),
            "mitigations_considered": f.get("mitigations_considered", ""),
            "confirmation_note": f.get("confirmation_note", ""),
        })
    return out


def build_summary_prompt(template: str, standard_text: str,
                         findings: list[dict], brief_text: str,
                         feedback_text: str, metadata: dict) -> str:
    payload = {
        "metadata": metadata,
        "counts": _counts(findings),
        "findings": _visible_finding_payload(findings),
    }
    return (
        template
        .replace("{{VULNERABILITY_HANDLING_STANDARD}}",
                 standard_text.strip())
        .replace("{{PROJECT_BRIEF}}", brief_text)
        .replace("{{SECURITY_SCAN_CONTEXT}}", feedback_text or "(none)")
        .replace("{{FINDINGS_JSON}}", json.dumps(payload, indent=2))
    )


def generate_business_summary(template: str, standard_text: str,
                              findings: list[dict],
                              brief_text: str, feedback_text: str,
                              metadata: dict, project_dir: str,
                              model: str, timeout: int) -> str:
    prompt = build_summary_prompt(
        template, standard_text, findings, brief_text, feedback_text, metadata
    )
    nudge = (
        "Your previous response could not be parsed. Respond with ONLY a JSON "
        "object of shape {\"summary\": \"...\"}."
    )
    value, raw = call_opencode_json(prompt, project_dir, model, timeout, nudge,
                                    phase="summary")
    if isinstance(value, dict):
        summary = str(value.get("summary", "") or "").strip()
        if summary:
            return summary
    return (
        "The business summary could not be generated automatically. "
        "Use the severity table and detailed findings below as the authoritative "
        "scanner output. Summary generation response: "
        f"{raw[-300:].strip()}"
    )
