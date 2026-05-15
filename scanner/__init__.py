"""Agentic white-box security scanner — modular package.

The top-level `security-scan.py` is the entry point; it re-exports this
package's public names so unit tests (which load the script file directly)
keep working without changes.

The codebase is intentionally function-based (no classes). Each module is
the unit you pick up; the pipeline order below mirrors a single scan run.

Pipeline order (executed by `cli.scan_project` for each project):

    1. cli.parse_args / main           — argparse + .env, per-project dispatch
    2. opencode_client                 — subprocess wrapper, retry, chatlogs
       (used by every phase below; nothing else talks to opencode)
    3. discovery (Phase 0)             — one LLM call, builds a project brief
    4. prompts                         — assembles cache-stable prompts
       (called by phases 3, 4, 5, 6, 7 — never holds state)
    5. dependency audit (Phase 1)      — one LLM call over manifests
       (driven directly from cli.scan_project; uses prompts + findings)
    6. perfile (Phase 2)               — one LLM call per source file (parallel)
    7. confirmation                    — re-verifies each finding, may
                                          downgrade severity / mark dropped
    8. dedup                           — deterministic merge, then semantic
                                          per-file LLM clustering
    9. summary                         — optional business-readable summary
   10. report.flush_reports            — single sink that writes
                                          vulnerabilities.{md,json} atomically

Cross-cutting modules:

    config              — constants, severity/confidence ordering tables
    findings            — finding-dict schema + LLM-output normalization
                          (used by every phase that produces findings)

`config` and `findings` are pure-data leaves. `prompts`, `opencode_client`,
`discovery`, `perfile`, `confirmation`, `summary`, and `dedup` depend
only on those leaves and on `opencode_client`. `report` additionally
depends on `dedup` so the final flush can re-run deterministic dedup.
`cli` is the only orchestrator and the only module that imports across
phases.
"""
