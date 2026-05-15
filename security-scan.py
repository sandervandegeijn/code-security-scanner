#!/usr/bin/env python3
"""
Agentic white-box security scanner built on opencode.

Entry point only. All logic lives in the `scanner/` package:

    scanner/config.py            constants
    scanner/discovery.py         file walk
    scanner/opencode_client.py   opencode invocation + JSON extraction
    scanner/prompts.py           prompt templating + directory tree
    scanner/findings.py          finding schema / normalization
    scanner/confirmation.py      confirmation pass
    scanner/perfile.py           per-file review wrapper
    scanner/dedup.py             deterministic + semantic dedup
    scanner/report.py            JSON/Markdown writers + flush pipeline
    scanner/cli.py               arg parsing + phase orchestration

Usage:
    python security-scan.py [options] <project_directory>

The unit tests load this file directly via importlib, so we re-export
the public (and underscore-prefixed internal) names tests reference.
"""

import sys

from scanner.cli import (  # noqa: F401
    finalize_and_report,
    main,
    parse_args,
    resolve_prompt_path,
    scan_project,
)
from scanner.config import (  # noqa: F401
    CONFIDENCE_ORDER,
    DEFAULT_EXCLUDE_DIRS,
    DEFAULT_EXCLUDE_FILES,
    DEFAULT_EXTENSIONS,
    DEFAULT_MODEL,
    DEFAULT_MODEL_HEAVY,
    DEFAULT_MODEL_LIGHT,
    DEFAULT_PARALLEL,
    INCLUDE_NO_EXT,
    SEVERITY_ORDER,
)
from scanner.confirmation import confirm_finding  # noqa: F401
from scanner.dedup import (  # noqa: F401
    _dedup_file_group,
    _dedupe_findings,
    _merge_into,
    _normalize_title,
    _parse_line_range,
    _pick_survivor_idx,
    _ranges_near,
    _titles_equivalent,
    semantic_dedup_pass,
)
from scanner.discovery import discover_all_files, discover_files  # noqa: F401
from scanner.findings import (  # noqa: F401
    REQUIRED_FINDING_FIELDS,
    normalize_finding,
    parse_failure_finding,
    parse_findings_array,
)
from scanner.opencode_client import (  # noqa: F401
    call_opencode,
    call_opencode_json,
    extract_json,
    extract_model_output,
    strip_ansi,
    summarize_stderr,
)
from scanner.perfile import scan_single_file  # noqa: F401
from scanner.prompts import (  # noqa: F401
    _FEEDBACK_CHAR_CAP,
    _MANIFEST_PER_FILE_CAP,
    _PROJECT_DOCS_CHAR_CAP,
    _TREE_CHAR_CAP,
    _is_manifest,
    build_confirmation_prompt,
    build_dependency_prompt,
    build_directory_tree,
    build_discovery_prompt,
    build_file_prompt,
    collect_manifest_contents,
    load_developer_feedback,
    load_project_docs,
    load_template,
)
from scanner.report import (  # noqa: F401
    _compute_sca_citation_audit,
    _finding_advisory_ids,
    _render_sca_state,
    flush_reports,
    render_brief_markdown,
    sort_findings,
    write_json_report,
    write_markdown_report,
)
from scanner.sca import (  # noqa: F401
    ScaRunResult,
    ScaState,
    db_state,
    ensure_osv_scanner,
    refresh_offline_db,
    run_osv_scan,
)
from scanner.summary import (  # noqa: F401
    build_summary_prompt,
    generate_business_summary,
)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted. Partial report (if any) left under ./output/.")
