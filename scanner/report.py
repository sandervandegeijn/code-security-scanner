"""JSON + Markdown report writers and the atomic flush pipeline.

`flush_reports` is the single sink: every other module routes its
write through it (Phase 0/1/2 progress flushes, the per-confirmation
flush, and the final post-dedup flush). The flush itself runs the
deterministic dedup once more — defence in depth in case a phase
appended duplicates after the main dedup pass.

Writes are atomic (`_atomic_write_text`): write to a sibling tmp file,
then rename. A SIGINT mid-scan still leaves a valid file on disk.
"""

import json
import re
from pathlib import Path

from .config import CONFIDENCE_ORDER, SEVERITY_ORDER
from .dedup import _dedupe_findings


def render_brief_markdown(brief: dict | None) -> str:
    if not isinstance(brief, dict):
        return "_No project brief available._\n"
    lines: list[str] = []
    stack = brief.get("stack", {}) or {}
    if stack:
        lines.append("**Stack**")
        for key in ("languages", "frameworks", "runtime", "package_managers"):
            val = stack.get(key)
            if not val:
                continue
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            lines.append(f"- {key.replace('_', ' ').title()}: {val}")
        lines.append("")

    auth = brief.get("auth", {}) or {}
    if auth:
        lines.append("**Authentication**")
        for key in ("mechanism", "authorization"):
            val = auth.get(key)
            if val:
                lines.append(f"- {key.title()}: {val}")
        files = auth.get("files") or []
        if files:
            lines.append(f"- Files: {', '.join(f'`{f}`' for f in files)}")
        lines.append("")

    for section, label in [
        ("entry_points", "Entry Points"),
        ("trust_boundaries", "Trust Boundaries"),
        ("shared_helpers", "Shared Helpers"),
    ]:
        items = brief.get(section) or []
        if items:
            lines.append(f"**{label}**")
            for item in items:
                if isinstance(item, dict):
                    desc = item.get("description") or item.get("purpose") or ""
                    files = item.get("files") or ([item.get("path")] if item.get("path") else [])
                    files = [f for f in files if f]
                    file_str = f" ({', '.join(f'`{f}`' for f in files)})" if files else ""
                    lines.append(f"- {desc}{file_str}")
                else:
                    lines.append(f"- {item}")
            lines.append("")

    cas = brief.get("config_and_secrets") or {}
    if cas:
        lines.append("**Config & Secrets**")
        for key in ("config_files", "secret_loading", "hardcoded_concerns"):
            val = cas.get(key)
            if not val:
                continue
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            lines.append(f"- {key.replace('_', ' ').title()}: {val}")
        lines.append("")

    risks = brief.get("notable_risks") or []
    if risks:
        lines.append("**Notable Risks**")
        for r in risks:
            lines.append(f"- {r}")
        lines.append("")

    return "\n".join(lines) if lines else "_No project brief available._\n"


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", ""), 99),
            CONFIDENCE_ORDER.get(f.get("confidence", ""), 99),
            f.get("file", ""),
        ),
    )


def _atomic_write_text(path: Path, text: str) -> None:
    """Write to a sibling .tmp and rename; external readers never see a
    half-written file. `Path.replace` is atomic on POSIX and Windows."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def write_json_report(path: Path, findings: list[dict], brief: object,
                      metadata: dict, business_summary: str = "") -> None:
    """Atomically write the machine-readable report. Called only from `flush_reports`."""
    payload = {
        "metadata": metadata,
        "project_brief": brief,
        "business_summary": business_summary,
        "findings": findings,
    }
    _atomic_write_text(path, json.dumps(payload, indent=2))


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-") or "finding"


def _loc(f: dict) -> str:
    loc = f.get("file", "")
    if f.get("line"):
        loc = f"{loc}:{f['line']}"
    return loc


def _severity_emoji(sev: str) -> str:
    return {"CRITICAL": "🟣", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "⚪"}.get(sev, "·")


def _md_escape_cell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


_ADVISORY_ID_RE = re.compile(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+)",
                              re.IGNORECASE)


_TEXT_FIELDS = ("title", "description", "evidence", "recommendation",
                "test_steps", "mitigations_considered",
                "confirmation_note", "dependency")


def _finding_text_blob(findings: list[dict]) -> str:
    """Concatenate every text-field value across every finding into one
    lower-cased blob. Used by the package-mention check so we can run
    one regex per package instead of per-(package × finding × field)."""
    parts: list[str] = []
    for f in findings:
        for field in _TEXT_FIELDS:
            value = f.get(field) or ""
            if isinstance(value, str) and value:
                parts.append(value)
    return "\n".join(parts).lower()


def _finding_advisory_ids(findings: list[dict]) -> set[str]:
    """Pull every CVE / GHSA identifier mentioned anywhere in any finding's
    text fields. Used to compute the SCA recall ratio against
    `metadata.sca.advisories`."""
    ids: set[str] = set()
    for f in findings:
        for field in _TEXT_FIELDS:
            value = f.get(field) or ""
            if not isinstance(value, str):
                continue
            for match in _ADVISORY_ID_RE.findall(value):
                ids.add(match.upper())
    return ids


def _package_mentioned(blob_lower: str, package: str) -> bool:
    """Return True if `package` appears as a whole-word token in the
    pre-lowered finding-text blob. Word boundaries prevent the
    `st`/`ms`/`q`/`is` false-match trap on common short package names."""
    if not package:
        return False
    pattern = r"\b" + re.escape(package.lower()) + r"\b"
    return re.search(pattern, blob_lower) is not None


def _compute_sca_citation_audit(findings: list[dict],
                                advisories: list[dict]) -> dict[str, object]:
    """Match the report's named CVE/GHSA IDs against the advisories
    osv-scanner produced. Returns a dict the report writer stamps into
    `metadata.sca` and consults when rendering the SCA audit trail.

    Each entry in `uncited_advisories` carries a `package_mentioned`
    flag so the rendered table can distinguish a *consolidation gap*
    (the package is discussed in some finding but the specific ID
    wasn't pasted) from a *genuine miss* (the package is nowhere in
    the report)."""
    cited = _finding_advisory_ids(findings)
    text_blob = _finding_text_blob(findings)
    pkg_mention_cache: dict[str, bool] = {}
    cited_against_osv: set[str] = set()
    uncited: list[dict[str, object]] = []
    seen_uncited: set[tuple[str, str, str]] = set()  # (pkg, ver, id)
    total_unique_ids: set[str] = set()
    for adv in advisories:
        if not isinstance(adv, dict):
            continue
        adv_id = str(adv.get("id", "")).upper()
        if not adv_id:
            continue
        total_unique_ids.add(adv_id)
        all_aliases = {adv_id, *(str(a).upper() for a in adv.get("aliases") or []
                                 if isinstance(a, (str, int)))}
        if all_aliases & cited:
            cited_against_osv.add(adv_id)
            continue
        key = (str(adv.get("package", "")), str(adv.get("version", "")), adv_id)
        if key in seen_uncited:
            continue
        seen_uncited.add(key)
        pkg_name = str(adv.get("package", ""))
        if pkg_name not in pkg_mention_cache:
            pkg_mention_cache[pkg_name] = _package_mentioned(text_blob, pkg_name)
        uncited.append({**adv, "package_mentioned": pkg_mention_cache[pkg_name]})
    total = len(total_unique_ids)
    recall_pct = round(100 * len(cited_against_osv) / total, 1) if total else 0.0
    return {
        "advisory_unique_id_count": total,
        "advisory_ids_cited_in_report": len(cited_against_osv),
        "advisory_recall_pct": recall_pct,
        "uncited_advisories": uncited,
    }


_AUDIT_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                         "INFO": 4, "": 5}


def _render_audit_trail_table(uncited: list[dict]) -> list[str]:
    """Render the SCA audit trail as `(package, ecosystem, advisory_id) →
    [versions]` rows, sorted worst-severity-first.

    One row per (package, advisory). Same advisory hitting three pinned
    versions of one package collapses into one row with the versions
    listed inline. Status column surfaces the consolidation-gap signal."""
    grouped: dict[tuple[str, str, str], dict[str, object]] = {}
    for adv in uncited:
        pkg = str(adv.get("package", ""))
        eco = str(adv.get("ecosystem", ""))
        adv_id = str(adv.get("id", ""))
        key = (pkg, eco, adv_id)
        bucket = grouped.setdefault(key, {
            "package": pkg, "ecosystem": eco, "id": adv_id,
            "versions": set(), "severity": str(adv.get("severity", "") or "").upper(),
            "package_mentioned": bool(adv.get("package_mentioned", False)),
        })
        ver = str(adv.get("version", ""))
        if ver:
            assert isinstance(bucket["versions"], set)
            bucket["versions"].add(ver)
        # Worst severity wins if entries disagree (rare — same advisory id
        # implies the same advisory).
        sev = str(adv.get("severity", "") or "").upper()
        if (_AUDIT_SEVERITY_RANK.get(sev, 5)
                < _AUDIT_SEVERITY_RANK.get(str(bucket["severity"]), 5)):
            bucket["severity"] = sev
        # `package_mentioned` is a per-package property; True wins.
        if adv.get("package_mentioned"):
            bucket["package_mentioned"] = True

    def sort_key(row: dict[str, object]) -> tuple[int, str, str]:
        sev = str(row.get("severity", ""))
        return (_AUDIT_SEVERITY_RANK.get(sev, 5),
                str(row.get("package", "")),
                str(row.get("id", "")))

    rows = sorted(grouped.values(), key=sort_key)

    lines: list[str] = []
    lines.append("| Sev | Package | Versions | Ecosystem | Advisory | Status |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for row in rows:
        sev = str(row.get("severity", ""))
        sev_cell = (f"{_severity_emoji(sev)} {sev}" if sev else "—")
        versions = sorted(v for v in row["versions"] if v) if isinstance(row["versions"], set) else []
        ver_cell = ", ".join(versions) if versions else "—"
        status = ("consolidation gap" if row.get("package_mentioned")
                  else "not in report")
        lines.append(
            f"| {sev_cell} | `{_md_escape_cell(str(row['package']))}` | "
            f"`{_md_escape_cell(ver_cell)}` | "
            f"{_md_escape_cell(str(row['ecosystem']))} | "
            f"{_md_escape_cell(str(row['id']))} | {status} |"
        )
    lines.append("")
    return lines


def _render_sca_state(sca_meta: object) -> str:
    """One italic line describing osv-scanner availability for this scan,
    so triagers reading the report know whether 'no Phase 1 CVEs' means
    'verified clean' or 'we couldn't check'."""
    if not isinstance(sca_meta, dict):
        return ""
    if sca_meta.get("available"):
        version = sca_meta.get("osv_scanner_version", "unknown")
        age = sca_meta.get("db_age_hours", "?")
        matches = sca_meta.get("advisory_match_count", 0)
        return (f"_SCA: osv-scanner v{version}, OSV DB refreshed {age}h ago, "
                f"{matches} advisory match(es) injected into Phase 1._")
    reason = sca_meta.get("reason") or "unknown"
    return (f"_SCA: unavailable ({reason}). Phase 1 used model knowledge only "
            "— see metadata.sca for details._")


def _first_sentence(text: str, limit: int = 160) -> str:
    text = (text or "").strip().replace("\n", " ")
    if not text:
        return ""
    m = re.search(r"[.!?](\s|$)", text)
    if m and m.start() < limit:
        return text[: m.start() + 1]
    return text[:limit] + ("…" if len(text) > limit else "")


def write_markdown_report(path: Path, findings: list[dict], brief: object,
                          metadata: dict, business_summary: str = "") -> None:
    """Atomically write the analyst-readable report. Called only from `flush_reports`."""
    visible_all = sort_findings([f for f in findings if not f.get("dropped")])
    dropped = [f for f in findings if f.get("dropped")]

    # Per-file findings drive the headline tables; dependency findings get
    # their own section below so the developer-facing fix list stays scannable.
    visible = [f for f in visible_all if f.get("phase") != "Dependency Audit"]
    dependencies = [f for f in visible_all if f.get("phase") == "Dependency Audit"]

    # Assign stable ids/anchors. Per-file uses `f<n>`; deps use `d<n>` so the
    # two namespaces don't collide.
    for i, f in enumerate(visible, 1):
        f["_id"] = i
        f["_anchor"] = f"f{i}-{_slug(f.get('title', ''))}"
    for i, f in enumerate(dependencies, 1):
        f["_id"] = i
        f["_anchor"] = f"d{i}-{_slug(f.get('title', ''))}"

    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    conf_counts = {"confirmed": 0, "likely": 0}
    for f in visible:
        sev_counts[f.get("severity", "INFO")] = sev_counts.get(f.get("severity", "INFO"), 0) + 1
        conf = f.get("confidence", "")
        if conf in conf_counts:
            conf_counts[conf] += 1

    # Group findings by file for the secondary view.
    by_file: dict[str, list[dict]] = {}
    for f in visible:
        by_file.setdefault(f.get("file", "(unknown)"), []).append(f)

    lines: list[str] = []
    lines.append(f"# Security Scan Report — `{metadata.get('project', '')}`")
    lines.append("")
    lines.append(f"- **Date:** {metadata.get('date', '')}")
    model_meta = metadata.get("model", "")
    if isinstance(model_meta, dict):
        heavy = model_meta.get("heavy", "")
        light = model_meta.get("light", "")
        lines.append(f"- **Model (heavy):** `{heavy}`")
        lines.append(f"- **Model (light):** `{light}`")
    else:
        # Back-compat: legacy single-string metadata from older runs.
        lines.append(f"- **Model:** `{model_meta}`")
    lines.append(f"- **Duration:** {metadata.get('duration', '')}")
    lines.append(
        f"- **Files:** discovered={metadata.get('files_discovered', 0)}, "
        f"scanned={metadata.get('files_scanned', 0)}, "
        f"skipped={metadata.get('files_skipped', 0)}"
    )
    lines.append("")

    # ---- Scan Summary (severity counts + management summary, headline band) ----
    dep_sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in dependencies:
        dep_sev_counts[f.get("severity", "INFO")] = (
            dep_sev_counts.get(f.get("severity", "INFO"), 0) + 1
        )

    lines.append("## Scan Summary")
    lines.append("")
    # Two side-by-side severity tables: source-code vs dependencies. Each
    # column header names which group its column counts.
    lines.append("| Severity | Source Code Findings | Vulnerable Dependencies |")
    lines.append("| --- | --- | --- |")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        emoji = _severity_emoji(sev)
        lines.append(
            f"| {emoji} {sev} | {sev_counts.get(sev, 0)} | "
            f"{dep_sev_counts.get(sev, 0)} |"
        )
    lines.append("")
    if business_summary.strip():
        lines.append("### Management Summary")
        lines.append("")
        lines.append(business_summary.strip())
        lines.append("")

    # Section transition: summary → overviews.
    lines.append("---")
    lines.append("")

    # ---- Source Code Findings — Overview ----
    lines.append("## Source Code Findings — Overview")
    lines.append("")
    if not visible:
        lines.append("_No source-code findings._")
        lines.append("")
    else:
        lines.append(
            "_Sorted by severity, then confidence, then file. Each row links to "
            "full detail under [Source Code Findings — Detail]"
            "(#source-code-findings--detail) below._"
        )
        lines.append("")
        lines.append("| # | Sev | Scanner/LLM verdict | Location | Title | What to do |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for f in visible:
            fix = _md_escape_cell(_first_sentence(f.get("recommendation", "")))
            lines.append(
                f"| {f['_id']} | {_severity_emoji(f['severity'])} **{f['severity']}** | "
                f"{f.get('confidence', '')} | "
                f"`{_md_escape_cell(_loc(f))}` | "
                f"[{f['title']}](#{f['_anchor']}) | "
                f"{fix} |"
            )
        lines.append("")

    # ---- Vulnerable Dependencies — Overview (sits next to source overview) ----
    lines.append("## Vulnerable Dependencies — Overview")
    lines.append("")
    if not dependencies:
        sca_meta = metadata.get("sca")
        if isinstance(sca_meta, dict) and sca_meta.get("no_sources"):
            # osv-scanner ran but found no manifests it can extract from.
            # Distinct from "scanner clean" (empty advisory list against real
            # manifests) and from "SCA failed" (degraded). Make the
            # difference explicit so triagers don't read "0 findings" as
            # "verified clean" or "tool broken".
            lines.append(
                "_No package manifests in formats `osv-scanner` recognises "
                "were found in this project (e.g. pure scripts, custom build "
                "systems, .NET `packages.config`-only projects). The Phase 1 "
                "LLM pass still ran on whatever manifests exist plus model "
                "training knowledge — but no deterministic CVE matching was "
                "possible._"
            )
        else:
            lines.append("_No dependency findings._")
        lines.append("")
    else:
        lines.append(
            "_Findings below come from `osv-scanner` (deterministic version-range "
            "matching against an offline OSV/GHSA snapshot) plus the LLM's "
            "contextual review of manifests. Each row links to full detail under "
            "[Vulnerable Dependencies — Detail]"
            "(#vulnerable-dependencies--detail) below._"
        )
        lines.append("")
        # Surface only the degraded-state stamp (so triagers know "0 dep
        # findings" doesn't mean "verified clean" when SCA was unavailable).
        # The success-state stamp was noisy and is removed.
        sca_meta = metadata.get("sca")
        if isinstance(sca_meta, dict) and not sca_meta.get("available"):
            lines.append(_render_sca_state(sca_meta))
            lines.append("")
        lines.append("| # | Sev | Dependency | Title | What to do |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in dependencies:
            fix = _md_escape_cell(_first_sentence(f.get("recommendation", "")))
            dep_label = _md_escape_cell(f.get("dependency", "") or f.get("file", ""))
            lines.append(
                f"| {f['_id']} | {_severity_emoji(f['severity'])} **{f['severity']}** | "
                f"`{dep_label}` | "
                f"[{f['title']}](#{f['_anchor']}) | "
                f"{fix} |"
            )
        lines.append("")

    # Section transition: overviews → per-file detail.
    lines.append("---")
    lines.append("")

    # ---- Source Code Findings — Detail ----
    if visible:
        lines.append("## Source Code Findings — Detail")
        lines.append("")
        lines.append("_Per-file findings from the source-code review pass, in the "
                     "same order as the overview table above._")
        lines.append("")
        for f in visible:
            lines.append(f'<a id="{f["_anchor"]}"></a>')
            header = f"### {f['_id']}. {_severity_emoji(f['severity'])} [{f['severity']}] {f['title']}"
            lines.append(header)
            lines.append("")
            loc = _loc(f)
            if loc:
                lines.append(f"**Location:** `{loc}`  ")
            lines.append(f"**Scanner/LLM verdict:** {f.get('confidence', '')}  ")
            if f.get("category"):
                lines.append(f"**Category:** {f['category']}  ")
            if f.get("dependency"):
                lines.append(f"**Dependency:** `{f['dependency']}`  ")
            lines.append(f"**Phase:** {f.get('phase', '')}")
            lines.append("")
            aliases = f.get("aliases") or []
            if aliases:
                alias_str = ", ".join(f"`{a}`" for a in aliases)
                lines.append(f"_Also reported as: {alias_str}_")
                lines.append("")
            if f.get("description"):
                lines.append(f"**Problem.** {f['description']}")
                lines.append("")
            if f.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("")
                lines.append("```")
                lines.append(f["evidence"])
                lines.append("```")
                lines.append("")
            if f.get("recommendation"):
                lines.append("**Recommended solution.**")
                lines.append("")
                lines.append(f["recommendation"])
                lines.append("")
            if f.get("test_steps"):
                lines.append(f"**Verify / reproduce.** {f['test_steps']}")
                lines.append("")
            if f.get("mitigations_considered"):
                lines.append(f"**Mitigations considered.** {f['mitigations_considered']}")
                lines.append("")
            if f.get("confirmation_note"):
                lines.append(f"**Confirmation note.** {f['confirmation_note']}")
                lines.append("")
            lines.append("---")
            lines.append("")

    # Section transition: per-file detail → dependency detail.
    if dependencies:
        lines.append("---")
        lines.append("")

    # ---- Vulnerable Dependencies — Detail ----
    if dependencies:
        lines.append("## Vulnerable Dependencies — Detail")
        lines.append("")
        lines.append("_Full detail for each dependency finding listed in the "
                     "overview table above._")
        lines.append("")
        for f in dependencies:
            lines.append(f'<a id="{f["_anchor"]}"></a>')
            lines.append(
                f"### D{f['_id']}. {_severity_emoji(f['severity'])} "
                f"[{f['severity']}] {f['title']}"
            )
            lines.append("")
            if f.get("dependency"):
                lines.append(f"**Dependency:** `{f['dependency']}`  ")
            if f.get("file"):
                lines.append(f"**Manifest:** `{f['file']}`  ")
            if f.get("category"):
                lines.append(f"**Category:** {f['category']}  ")
            lines.append("**Source:** osv-scanner advisory match (deterministic)")
            lines.append("")
            aliases = f.get("aliases") or []
            if aliases:
                alias_str = ", ".join(f"`{a}`" for a in aliases)
                lines.append(f"_Also reported as: {alias_str}_")
                lines.append("")
            if f.get("description"):
                lines.append(f"**Problem.** {f['description']}")
                lines.append("")
            if f.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("")
                lines.append("```")
                lines.append(f["evidence"])
                lines.append("```")
                lines.append("")
            if f.get("recommendation"):
                lines.append("**Recommended solution.**")
                lines.append("")
                lines.append(f["recommendation"])
                lines.append("")
            if f.get("test_steps"):
                lines.append(f"**Verify / reproduce.** {f['test_steps']}")
                lines.append("")
            if f.get("mitigations_considered"):
                lines.append(f"**Mitigations considered.** {f['mitigations_considered']}")
                lines.append("")
            lines.append("---")
            lines.append("")

    # ---- Vulnerable Dependencies — SCA Audit Trail ----
    # Lists every osv-scanner advisory match that the LLM did *not* explicitly
    # name in any finding. Lets a triager comparing the report against raw
    # osv-scanner output see the consolidation delta at a glance.
    sca_meta = metadata.get("sca")
    if (isinstance(sca_meta, dict)
            and sca_meta.get("advisory_unique_id_count")):
        uncited = sca_meta.get("uncited_advisories") or []
        cited = sca_meta.get("advisory_ids_cited_in_report", 0)
        total = sca_meta.get("advisory_unique_id_count", 0)
        recall = sca_meta.get("advisory_recall_pct", 0)
        lines.append("---")
        lines.append("")
        lines.append("## Vulnerable Dependencies — SCA Audit Trail")
        lines.append("")
        lines.append(
            f"_osv-scanner produced **{total} unique advisory IDs** across the "
            f"project's manifests. Findings above explicitly cite **{cited}** of them "
            f"(**{recall}% recall**). The table lists each uncited advisory once "
            "per package, with every affected installed version inline. The "
            "**Status** column distinguishes a `consolidation gap` (the package "
            "is discussed in some finding but the specific ID wasn't pasted into "
            "the description text) from `not in report` (the package isn't named "
            "anywhere — a genuine miss worth investigating). Rows are ordered "
            "worst-severity-first so the most exposed misses surface at the top._"
        )
        lines.append("")
        if not uncited:
            lines.append("_All osv-scanner advisories are named in the findings above._")
            lines.append("")
        else:
            lines.extend(_render_audit_trail_table(uncited))

    # ---- Secondary view: source-code findings grouped by file ----
    if by_file:
        lines.append("---")
        lines.append("")
        lines.append("## Source Code Findings — By File")
        lines.append("")
        lines.append("_Same source-code findings as above, grouped by the file "
                     "they cite. Useful when fixing a single file end-to-end._")
        lines.append("")
        def _file_group_severity_key(file_findings_pair):
            """Sort key for the by-file view: worst severity in the group, then path."""
            path_, fs = file_findings_pair
            worst_severity = min(SEVERITY_ORDER.get(x.get("severity", ""), 99) for x in fs)
            return (worst_severity, path_)
        for file_, fs in sorted(by_file.items(), key=_file_group_severity_key):
            sev_mix = " ".join(
                f"{_severity_emoji(s)}{sum(1 for x in fs if x['severity'] == s)}"
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                if any(x["severity"] == s for x in fs)
            )
            lines.append(f"### `{file_}` — {sev_mix}")
            lines.append("")
            lines.append("| Sev | Scanner/LLM verdict | Line | Title |")
            lines.append("| --- | --- | --- | --- |")
            for f in fs:
                lines.append(
                    f"| {_severity_emoji(f['severity'])} {f['severity']} | "
                    f"{f.get('confidence', '')} | "
                    f"`{_md_escape_cell(f.get('line', '') or '-')}` | "
                    f"[{f['title']}](#{f['_anchor']}) |"
                )
            lines.append("")

    # Section transition: findings → context.
    lines.append("---")
    lines.append("")

    # ---- Project Brief ----
    lines.append("## Project Brief")
    lines.append("")
    lines.append(render_brief_markdown(brief if isinstance(brief, dict) else None))
    lines.append("")

    # ---- Dropped ----
    if dropped:
        lines.append("## Dropped (false positives)")
        lines.append("")
        lines.append("These findings were raised by the initial pass but rejected "
                     "by the confirmation pass. Listed for auditability.")
        lines.append("")
        lines.append("| Severity | Location | Title | Reason |")
        lines.append("| --- | --- | --- | --- |")
        for f in sort_findings(dropped):
            lines.append(
                f"| {f['severity']} | `{_md_escape_cell(_loc(f))}` | "
                f"{f['title']} | {_md_escape_cell(f.get('confirmation_note', ''))} |"
            )
        lines.append("")

    _atomic_write_text(path, "\n".join(lines))

    # Clean the transient ids we stamped on; don't leak them into JSON.
    for f in visible:
        f.pop("_id", None)
        f.pop("_anchor", None)
    for f in dependencies:
        f.pop("_id", None)
        f.pop("_anchor", None)


def flush_reports(md_path: Path, json_path: Path, findings: list[dict],
                  brief: object, metadata: dict,
                  business_summary: str = "") -> None:
    """
    Dedupe findings once, here, before writing either artifact. Both the JSON
    and the MD report see the same collapsed list. Duplicates (same
    title+file+line) are merged into the first occurrence, keeping the best
    confidence seen.

    Snapshots each finding so concurrent mutation during parallel phases
    (notably the confirmation pass, which mutates findings in place from
    worker threads) can't bleed half-applied state into the rendered output.
    Aliases is the only nested mutable we deep-copy; other values are
    immutable scalars.
    """
    snapshot: list[dict] = []
    for f in findings:
        copy = dict(f)
        aliases = copy.get("aliases")
        if isinstance(aliases, list):
            copy["aliases"] = list(aliases)
        snapshot.append(copy)
    visible = [f for f in snapshot if not f.get("dropped")]
    dropped = [f for f in snapshot if f.get("dropped")]
    deduped, _collapsed = _dedupe_findings(visible)
    combined = deduped + dropped

    # Compute the SCA citation audit deterministically against the final
    # finding list so JSON consumers and the MD appendix see the same
    # recall metrics. Doesn't run an LLM — pure regex over text fields.
    metadata = dict(metadata)
    sca_meta = metadata.get("sca")
    if isinstance(sca_meta, dict):
        advisories = sca_meta.get("advisories") or []
        if isinstance(advisories, list) and advisories:
            audit = _compute_sca_citation_audit(combined, advisories)
            sca_meta = {**sca_meta, **audit}
            metadata["sca"] = sca_meta

    write_json_report(json_path, combined, brief, metadata, business_summary)
    write_markdown_report(md_path, combined, brief, metadata, business_summary)
