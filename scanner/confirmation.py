"""Confirmation pass — re-verifies each finding with a fresh LLM call.

Runs after every finding-producing phase (`perfile`, dependency audit).
The model returns one of `confirmed` / `likely` / `false_positive`;
false positives are flagged `dropped` (kept in JSON for auditability,
collapsed into a footer table in the markdown report). May also return
`severity_override` to downgrade an over-rated finding — applied only
when the verdict isn't `false_positive` (overrides on dropped findings
are intentionally ignored).

Invoked from `cli.finalize_and_report` once per finding, in parallel.
"""

from .config import CONFIDENCE_ORDER, SEVERITY_ORDER
from .opencode_client import call_opencode_json
from .prompts import build_confirmation_prompt


def confirm_finding(finding: dict, brief_text: str, tree_text: str,
                    feedback_text: str, template: str, project_dir: str,
                    model: str, timeout: int) -> dict:
    prompt = build_confirmation_prompt(template, brief_text, tree_text,
                                       feedback_text, finding)
    nudge = (
        "Your previous response could not be parsed. Respond with ONLY a JSON "
        "object of shape {\"confidence\": \"...\", \"note\": \"...\", "
        "\"severity_override\": \"\"}."
    )
    value, _raw = call_opencode_json(prompt, project_dir, model, timeout, nudge,
                                     phase="confirm")
    if isinstance(value, dict):
        confidence = str(value.get("confidence", "")).strip().lower()
        note = str(value.get("note", "")).strip()
        override_raw = str(value.get("severity_override", "") or "").strip().upper()
    else:
        confidence, note, override_raw = "", "", ""

    if confidence not in CONFIDENCE_ORDER:
        # Fail safe: don't silently drop a finding when confirmation itself failed.
        finding["confidence"] = "likely"
        finding["confirmation_note"] = (
            note or "Confirmation pass failed to return a valid verdict; defaulting to 'likely'."
        )
    else:
        finding["confidence"] = confidence
        finding["confirmation_note"] = note

    # Apply severity override only when the verdict wasn't a false positive
    # (false positives get dropped anyway) and the override is a valid tier
    # different from the current one.
    if (
        override_raw
        and override_raw in SEVERITY_ORDER
        and finding.get("confidence") != "false_positive"
        and override_raw != finding.get("severity", "").upper()
    ):
        old_sev = finding.get("severity", "")
        finding["severity"] = override_raw
        adjustment = f"severity adjusted {old_sev} → {override_raw}"
        existing = finding.get("confirmation_note") or ""
        finding["confirmation_note"] = (
            f"{adjustment}: {existing}" if existing else adjustment
        )

    finding["dropped"] = (finding["confidence"] == "false_positive")
    return finding
