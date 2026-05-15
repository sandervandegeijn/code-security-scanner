"""Finding deduplication — deterministic + semantic, in that order.

Stage 1 (`_dedupe_findings`): purely local heuristics. Merges findings
in the same file with equivalent titles and overlapping/near line
ranges. Cheap, deterministic, no LLM calls.

Stage 2 (`semantic_dedup_pass`): one per-file LLM call that clusters
findings with different titles describing the same root cause. The
canonical title wins; the dropped titles are preserved as `aliases`
so the audit trail stays intact.

Both stages run after the confirmation pass, from
`cli.finalize_and_report`. The deterministic helpers are exercised
directly by `tests/test_security_scan.py` — change a threshold here
and the tests must move with it.
"""

import concurrent.futures
import json
import re

from .config import CONFIDENCE_ORDER, SEVERITY_ORDER
from .opencode_client import call_opencode_json


# ---------------------------------------------------------------------------
# Deterministic dedup helpers
# ---------------------------------------------------------------------------

# Pulls every decimal integer out of a "line" field like "42" or "42-48".
_LINE_RANGE_RE = re.compile(r"(\d+)")
# Strips everything that isn't a-z/0-9 so "SQL Injection" == "sql_injection".
_TITLE_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def _parse_line_range(raw: object) -> tuple[int, int]:
    """Normalize a finding's line field to (start, end). Empty/unparseable → (0, 0)."""
    text = str(raw or "").strip()
    if not text:
        return (0, 0)
    nums = [int(m) for m in _LINE_RANGE_RE.findall(text)]
    if not nums:
        return (0, 0)
    if len(nums) == 1:
        return (nums[0], nums[0])
    return (min(nums), max(nums))


def _normalize_title(title: str) -> str:
    return _TITLE_NORMALIZE_RE.sub("", (title or "").lower())


def _titles_equivalent(a: str, b: str) -> bool:
    """Equal after normalization, OR one is a prefix of the other and the
    shorter is at least 6 chars and covers ≥70% of the longer. This catches
    BYPASS/BYPASSED, SQL_INJECTION/SQL_INJECTION_IN_QUERY, etc."""
    if a == b:
        return True
    if not a or not b:
        return False
    shorter_title, longer_title = (a, b) if len(a) <= len(b) else (b, a)
    if len(shorter_title) < 6:
        return False
    if not longer_title.startswith(shorter_title):
        return False
    return len(shorter_title) / len(longer_title) >= 0.7


def _ranges_near(a: tuple[int, int], b: tuple[int, int], slack: int = 3) -> bool:
    """True if ranges overlap or are within `slack` lines. (0,0) matches only (0,0)."""
    if a == (0, 0) or b == (0, 0):
        return a == b
    return not (a[1] + slack < b[0] or b[1] + slack < a[0])


def _merge_into(kept: dict, dropped: dict) -> None:
    """Merge `dropped` into `kept` in place, preferring better confidence and
    retaining the dropped title as an alias."""
    kept_conf = CONFIDENCE_ORDER.get(kept.get("confidence", ""), 99)
    this_conf = CONFIDENCE_ORDER.get(dropped.get("confidence", ""), 99)
    if this_conf < kept_conf:
        kept["confidence"] = dropped.get("confidence", kept.get("confidence", ""))
        kept["confirmation_note"] = (
            dropped.get("confirmation_note") or kept.get("confirmation_note", "")
        )
    dropped_title = (dropped.get("title") or "").strip()
    if dropped_title and dropped_title != kept.get("title", ""):
        aliases = kept.setdefault("aliases", [])
        if dropped_title not in aliases:
            aliases.append(dropped_title)
    # Carry over any aliases the dropped finding already accumulated.
    for alias in dropped.get("aliases", []) or []:
        aliases = kept.setdefault("aliases", [])
        if alias and alias != kept.get("title", "") and alias not in aliases:
            aliases.append(alias)


def _dedupe_findings(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Deterministic dedup. Collapses findings that are the same issue under:
      - exact match on (title, file, line); or
      - same file, overlapping-or-near line ranges (±3), and title-equal-after
        lowercasing + stripping non-alphanumerics (catches BYPASS vs BYPASSED).
    Kept finding retains the best confidence seen; dropped titles become aliases.
    Returns (deduped_findings, dropped_duplicates).
    """
    order: list[dict] = []
    dupes: list[dict] = []
    # Index survivors by file so fuzzy matching is O(dupes-per-file), not O(N).
    by_file: dict[str, list[dict]] = {}

    for f in findings:
        file_ = f.get("file", "")
        rng = _parse_line_range(f.get("line", ""))
        norm_title = _normalize_title(f.get("title", ""))

        match: dict | None = None
        for candidate in by_file.get(file_, []):
            cand_rng = _parse_line_range(candidate.get("line", ""))
            cand_norm = _normalize_title(candidate.get("title", ""))
            if _titles_equivalent(cand_norm, norm_title) and _ranges_near(rng, cand_rng):
                match = candidate
                break

        if match is not None:
            _merge_into(match, f)
            dupes.append(f)
            continue

        order.append(f)
        by_file.setdefault(file_, []).append(f)

    return order, dupes


# ---------------------------------------------------------------------------
# Semantic dedup pass (per-file LLM clustering)
# ---------------------------------------------------------------------------

def _pick_survivor_idx(cluster_findings: list[dict]) -> int:
    """Best severity, then best confidence, then first by input order."""
    best = 0
    for i in range(1, len(cluster_findings)):
        a = cluster_findings[i]
        b = cluster_findings[best]
        a_sev = SEVERITY_ORDER.get(a.get("severity", ""), 99)
        b_sev = SEVERITY_ORDER.get(b.get("severity", ""), 99)
        if a_sev < b_sev:
            best = i
            continue
        if a_sev > b_sev:
            continue
        a_conf = CONFIDENCE_ORDER.get(a.get("confidence", ""), 99)
        b_conf = CONFIDENCE_ORDER.get(b.get("confidence", ""), 99)
        if a_conf < b_conf:
            best = i
    return best


def _valid_cluster_indices(raw_ids: list, group_size: int) -> list[int]:
    """Coerce LLM-returned cluster ids to in-range integer indices."""
    valid: list[int] = []
    for value in raw_ids:
        if not isinstance(value, (int, float)):
            continue
        index = int(value)
        if 0 <= index < group_size:
            valid.append(index)
    return valid


def _dedup_file_group(file_: str, group: list[dict], brief_text: str,
                      tree_text: str, template: str, project_dir: str,
                      model: str, timeout: int) -> list[dict]:
    """
    Ask the LLM which findings in one file refer to the same root cause.
    Returns the kept subset; clustered duplicates are merged into survivors
    (title replaced with canonical_title, dropped titles go into `aliases`).
    """
    if len(group) < 2:
        return group

    condensed = [
        {
            "id": i,
            "title": f.get("title", ""),
            "line": f.get("line", ""),
            "severity": f.get("severity", ""),
            "category": f.get("category", ""),
            "description": (f.get("description", "") or "")[:400],
        }
        for i, f in enumerate(group)
    ]
    prompt = (
        template
        .replace("{{PROJECT_BRIEF}}", brief_text)
        .replace("{{DIRECTORY_TREE}}", tree_text)
        .replace("{{FILE}}", file_)
        .replace("{{FINDINGS_JSON}}", json.dumps(condensed, indent=2))
    )
    nudge = (
        "Your previous response could not be parsed. Respond with ONLY a JSON "
        "object of shape {\"clusters\": [{\"ids\": [..], \"canonical_title\": \"..\", "
        "\"reason\": \"..\"}]}. Omit clusters of size 1."
    )
    value, _raw = call_opencode_json(prompt, project_dir, model, timeout, nudge,
                                     phase="dedup")
    if not isinstance(value, dict):
        return group
    clusters = value.get("clusters")
    if not isinstance(clusters, list):
        return group

    dropped_ids: set[int] = set()
    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        ids = cluster.get("ids")
        if not isinstance(ids, list) or len(ids) < 2:
            continue
        member_ids = _valid_cluster_indices(ids, len(group))
        # Exclude already-merged ids (can happen if LLM overlaps clusters).
        member_ids = [i for i in member_ids if i not in dropped_ids]
        if len(member_ids) < 2:
            continue
        canonical = str(cluster.get("canonical_title", "")).strip()
        reason = str(cluster.get("reason", "")).strip()
        members = [group[i] for i in member_ids]
        survivor_local = _pick_survivor_idx(members)
        survivor = members[survivor_local]
        for idx, member in enumerate(members):
            if idx == survivor_local:
                continue
            _merge_into(survivor, member)
        if canonical and canonical != survivor.get("title", ""):
            old_title = survivor.get("title", "").strip()
            if old_title:
                aliases = survivor.setdefault("aliases", [])
                if old_title not in aliases and old_title != canonical:
                    aliases.append(old_title)
            survivor["title"] = canonical
        if reason:
            existing_note = (survivor.get("confirmation_note") or "").strip()
            merged_note = f"{existing_note} | dedup: {reason}" if existing_note else f"dedup: {reason}"
            survivor["confirmation_note"] = merged_note
        for i in member_ids:
            if i != member_ids[survivor_local] and group[i] is not survivor:
                dropped_ids.add(i)
        # Track the survivor's own global id so overlapping clusters don't re-process.
        dropped_ids.discard(member_ids[survivor_local])

    return [f for i, f in enumerate(group) if i not in dropped_ids]


def semantic_dedup_pass(findings: list[dict], brief_text: str, tree_text: str,
                        template: str, project_dir: str, model: str,
                        timeout: int, parallel: int) -> list[dict]:
    """
    Run a per-file LLM clustering pass over visible (non-dropped) findings.
    Dropped findings are passed through untouched. Returns the new finding list.
    """
    visible = [f for f in findings if not f.get("dropped")]
    dropped = [f for f in findings if f.get("dropped")]

    by_file: dict[str, list[dict]] = {}
    for f in visible:
        by_file.setdefault(f.get("file", ""), []).append(f)

    multi_file_groups = {k: v for k, v in by_file.items() if len(v) >= 2}
    passthrough = [f for k, v in by_file.items() if len(v) < 2 for f in v]

    if not multi_file_groups:
        return visible + dropped

    candidate_count = sum(len(v) for v in multi_file_groups.values())
    skipped_singletons = len(passthrough)
    print(
        "[Dedup] Semantic candidates: "
        f"{candidate_count} kept finding(s) across {len(multi_file_groups)} cited file(s); "
        f"{skipped_singletons} single-file finding(s) have no same-file peer and are skipped.",
        flush=True,
    )

    results: list[dict] = []
    max_workers = min(parallel, len(multi_file_groups))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _dedup_file_group, file_, group, brief_text, tree_text,
                template, project_dir, model, timeout
            ): file_
            for file_, group in multi_file_groups.items()
        }
        for future in concurrent.futures.as_completed(futures):
            file_ = futures[future]
            try:
                kept = future.result()
            except Exception as exc:
                print(f"[Dedup] {file_}: pass failed ({exc}); keeping originals.", flush=True)
                kept = multi_file_groups[file_]
            collapsed = len(multi_file_groups[file_]) - len(kept)
            if collapsed > 0:
                print(
                    f"[Dedup] {file_}: collapsed {collapsed} duplicate report(s); "
                    f"kept {len(kept)} finding(s).",
                    flush=True,
                )
            results.extend(kept)

    return passthrough + results + dropped
