# CLAUDE.md

Guidance for future Claude sessions working on this repository.

## What this is

An agentic white-box security scanner that drives the `opencode` CLI. It
walks a target project, asks an LLM to audit it in four phases, and writes
an analyst report (`vulnerabilities.md`) and a machine-readable JSON.

Entry point: `security-scan.py` (single-file script; no package install).

## Pipeline

1. **Phase 0 — Discovery**: one LLM call produces a project brief (stack,
   auth, trust boundaries, shared helpers). Kept in memory for the current
   scan run and reused by later phases. The prompt now also receives the
   project's own top-level docs (`README.md`, `SECURITY.md`,
   `ARCHITECTURE.md`, `CONTRIBUTING.md`, and any `docs/*.md`) via
   `load_project_docs` so the model anchors its claims to documented
   intent rather than filename guesses. See "Project docs auto-load" below.
2. **Phase 1 — Dependency audit**: one call over all manifests.
3. **Phase 2 — Per-file review**: one call per source file, parallelised.
   Manifests covered by Phase 1 (`package.json`, `pom.xml`, `composer.json`,
   `pubspec.yaml`, `bower.json`, plus all lockfiles) are excluded from
   Phase 2 via `DEFAULT_EXCLUDE_FILES` to avoid cross-phase overlap.
4. **Confirmation pass**: re-verifies *only per-file* findings
   (`confirmed`/`likely`/`false_positive`). Dependency findings produced
   by Phase 1 are marked `confirmed` deterministically (osv-scanner
   advisory matches don't need LLM re-verification) and skip the
   confirmation LLM call. False positives are marked `dropped` (kept in
   JSON for auditability, listed at the bottom of the MD).
5. **Dedup pass** — two stages, runs after confirmation:
   - **Deterministic** (`_dedupe_findings`): merges exact matches and
     range-wiggle/title-prefix duplicates.
   - **Semantic LLM** (`semantic_dedup_pass`): per-file clustering call
     that collapses findings with different titles describing the same
     root cause. Canonical title wins, dropped titles become `aliases`.

## Layout

`security-scan.py` is the entry point (re-exports symbols for tests).
The `scanner/` package holds: `config`, `discovery`, `opencode_client`,
`prompts`, `findings`, `confirmation`, `perfile`, `dedup`, `report`,
`sca`, `summary`, `cli`. Prompts live in `./prompts/`, default scan
target in `./input/`, reports in `./output/<YYYY-MM-DD_HH-MM>/`.
`opencode.json` (committed) defines the read-only `scanner` agent jail.

## Configuration: `.env` at the repo root

Most scan settings (model, parallelism, timeouts, file-size cap,
extension filter, exclude-dirs, OSV paths, the five `--skip-*` toggles)
live in `./.env`. Each setting is documented inline. Edit it instead of
memorising flags.

Precedence (highest wins): CLI flag → real env var → `.env` value →
hardcoded fallback in `scanner/config.py` / `scanner/cli.py`.

Per-invocation things stay CLI-only: positional `project_dirs`,
`--output`, `--dry-run`, `--dependencies-only`, `--print-prompt`,
`--refresh-osv-db`. They have no `.env` equivalents on purpose — they
vary every run.

Project-stable settings (`SCAN_MAX_FILE_SIZE`, `SCAN_EXTENSIONS`,
`SCAN_EXCLUDE_DIRS`, `SCAN_FEEDBACK_DIR`) are **`.env`-only** —
intentionally no CLI flag. They're either set once per project or
forgotten, and double-exposing them clutters `--help`.

The loader is a 15-line parser in `scanner/cli.py:_load_dotenv` (no
`python-dotenv` dep). `KEY=VALUE`, `#` comments, blank lines. No
quoting, no interpolation, no multi-line values.

## Models and provider

**Two-slot model split** (set in `.env`, no CLI flag):

- `SCAN_MODEL_HEAVY` (default `azure/gpt-5.5`) — runs every assessment
  phase: discovery, dependency audit, per-file review, confirmation.
  This is where scan accuracy lives.
- `SCAN_MODEL_LIGHT` (default `azure/gpt-5.4-mini`) — runs the
  structural post-processing only: semantic dedup clustering and the
  business summary. Quality impact on actual findings is minimal
  because the heavy model has already produced and confirmed them by
  this point.

Legacy back-compat: if `.env` only sets `SCAN_MODEL=...` and leaves
both `_HEAVY` / `_LIGHT` empty, the single value fills both slots —
old configs keep working until they opt into the split. There is
deliberately no `--model` CLI flag; per-call overrides go through
`.env`, matching the project-stable settings pattern
(`SCAN_MAX_FILE_SIZE` etc.).

Per-phase mapping is in `scanner/cli.py:scan_project` /
`finalize_and_report` — `args.model_heavy` is threaded into discovery
(line ~593), dependency (~631), per-file (~681), confirmation
(~756); `args.model_light` into semantic dedup (~814) and summary
(~841). Defaults: `DEFAULT_MODEL_HEAVY` / `DEFAULT_MODEL_LIGHT` in
`scanner/config.py`. `DEFAULT_MODEL` is kept as a back-compat alias
that resolves to the heavy slot.

`metadata.model` in `vulnerabilities.json` is now a `{heavy, light}`
object; the MD report header renders both lines
(`scanner/report.py`). The legacy single-string form is still
accepted on read for older JSON reports.

Provider config lives in `~/.config/opencode/opencode.json` (outside the
repo). That's where the Azure endpoint and deployments are wired up.
Anything that changes model behaviour — deployments added, API version
bumps — happens there, not here.

Quick check a model is reachable:
```bash
opencode run --model azure/gpt-5.4-mini "say hi"
```

### When to use which model

- **`gpt-5.5` (heavy default)** — primary assessment model. Use the
  highest-quality model you have access to.
- **`gpt-5.4-mini` (light default)** — sufficient for dedup
  clustering and business-summary writing. Roughly an order of
  magnitude cheaper per token.
- **`gpt-5.3-codex`** — alternative heavy model. Higher recall but
  noisier; catches things 5.5 misses (debug/legacy endpoints, subtle
  auth flaws) at the cost of more duplicates and FPs. Don't try to
  merge codex + 5.5 outputs automatically — severity calibration
  differs.

Typical workflow: keep the defaults; re-run with `SCAN_MODEL_HEAVY=azure/gpt-5.3-codex`
occasionally and diff against a 5.5 run.

## Prompt caching — placeholder order matters

Per-file, confirmation and dedup prompts all share the same cache-stable
prefix across every call in a scan:

```
[template]  [{{PROJECT_BRIEF}}]  [{{DIRECTORY_TREE}}]  ... then variable ...
```

Everything before the variable block (`{{FILENAME}}` / `{{FINDING_JSON}}` /
`{{FINDINGS_JSON}}`) is identical for every call in the project, which is
what Azure's prefix cache keys on. **Do not move placeholders past the
variable block** or insert per-call data earlier — you'll break cache
hits and roughly double the token bill on any large project.

The tree itself is produced deterministically by `build_directory_tree`
(relative paths, sorted, grouped-by-directory, capped at `_TREE_CHAR_CAP`
~= 40 KB) so bytes are stable run-to-run.

## Project docs auto-load (Phase 0 context)

`load_project_docs` (`scanner/prompts.py`) reads the project's own
top-level docs and injects them into the discovery prompt via
`{{PROJECT_DOCS}}`. This runs unconditionally — independent of
`SECURITY_SCAN.md` / developer feedback, which is a separate trust
channel.

Candidate list (relative to the scanned project root,
case-insensitive on basename):

- `README.md`
- `SECURITY.md`
- `ARCHITECTURE.md`
- `CONTRIBUTING.md`
- `docs/*.md` (non-recursive, sorted)

Missing/empty files are skipped. Total bundle is soft-capped at
`_PROJECT_DOCS_CHAR_CAP` (40 KB), separate from
`_FEEDBACK_CHAR_CAP` so a chunky README doesn't squeeze feedback or
vice-versa. Output blocks are `=== <relative-path> ===\n<content>`
separated by blank lines (same shape as developer feedback).

Wired into Phase 0 only — later phases inherit project context via
the `{{PROJECT_BRIEF}}` placeholder, which is the discovery output
condensed into JSON. The discovery prompt frames the docs as
*maintainer intent* and tells the model to verify load-bearing
claims against actual code.

Trust note: project docs are part of the scanned codebase. They are
*not* a clean instruction channel — a malicious README could prompt-
inject. Same risk model as scanning any source file. Don't scan
untrusted projects.

## Developer feedback (`input/feedback/*.md`)

Loaded by `load_developer_feedback` (`scanner/prompts.py`) and injected
into the per-file, dependency-audit, and confirmation prompts via the
new `{{DEVELOPER_FEEDBACK}}` placeholder, after `{{DIRECTORY_TREE}}`
in the cache-stable prefix.

Behaviour:

- Recursive `*.md` walk, sorted by relative POSIX path. Top-level
  `README.md` is skipped (it's the directory's own how-to template).
- Empty files are dropped. Total bundle is soft-capped at
  `_FEEDBACK_CHAR_CAP` (40 KB) with a truncation marker.
- Output blocks are `=== <relative-path> ===\n<content>` separated by
  blank lines.
- Discovery (Phase 0) and dedup do **not** receive feedback —
  discovery is project-mapping, dedup is duplicate detection. Both
  would be hurt by adjudication context.

Resolution order in `_resolve_feedback_dir` (`scanner/cli.py`):

1. `--feedback-dir` / `SCAN_FEEDBACK_DIR` if explicitly set.
2. `<project_dir>/SECURITY_SCAN.md`.
3. If exactly one immediate visible subdirectory of `<project_dir>`
   contains a `SECURITY_SCAN.md`, return that path. If two or more
   subdirs match, refuse to guess (warn loudly with all candidates).
4. Otherwise `None` — no feedback is loaded.

Every run prints exactly one `[Feedback]` line at startup naming the
resolved file (or explaining why none was loaded). See
`_log_feedback_resolution`.

Trust boundary: feedback content is concatenated verbatim into prompts
with explicit "treat as authoritative" framing. A malicious file can
prompt-inject the model into ignoring real vulnerabilities. Only the
team running the scan should write there. This is documented in
`input/feedback/README.md` and the README.

## Mitigations and severity adjustment

Two mechanisms keep severity honest when defences are in place:

1. **Phase 2 mitigations ladder** (`security-prompt.md`): the model is
   told to look for parameterisation / validation / auth gating /
   framework escaping before picking severity. Tiers:
   - Partial mitigation → drop one tier (HIGH → MEDIUM).
   - Substantial-with-narrow-residual → drop two tiers (HIGH → LOW).
   - **Fully mitigated by an upstream layer → raise as LOW with
     `confidence: likely`**, framed as defence-in-depth. The
     `mitigations_considered` field quotes the upstream guard so the
     auditor sees that the pattern was noticed and the upstream
     coverage was identified. Do **not** drop fully-mitigated
     findings silently — historic behaviour was to drop them, but the
     audit trail is more valuable than the noise reduction. The
     confirmation prompt mirrors this: a covered-upstream verdict
     emits `severity_override: LOW` + `confidence: likely`, never
     `false_positive`.
2. **Confirmation-pass override** (`confirm_finding`): the confirmation
   response may include `severity_override` in `{CRITICAL|HIGH|MEDIUM|
   LOW|INFO}`. If it's valid, differs from the current severity, and the
   verdict isn't `false_positive`, the finding's `severity` is mutated
   and the change is prepended to `confirmation_note` as
   `severity adjusted HIGH → MEDIUM: ...`.

An override on a `false_positive` verdict is intentionally ignored —
false positives get dropped, not re-tiered. Invalid override values are
silently ignored.

If you change the LOW-defence-in-depth rule, **update both prompts and
the security-prompt severity ladder together**. They reference each
other by tier; out-of-sync prompts produce inconsistent verdicts that
the confirmation pass can't resolve.

## Severity rubric (calibration is prompt-driven)

Lives in `prompts/security-prompt.md` and `prompts/confirmation-prompt.md`.
Both prompts must agree or the confirmation pass destabilises ratings.

- **CRITICAL**: pre-auth RCE / auth bypass / hardcoded prod secrets in
  source / unauthenticated admin or reset endpoints.
- **HIGH**: authenticated RCE, injection behind auth, weak crypto in
  session/reset tokens, **EOL runtime or application framework targeted
  by the whole project** (e.g. .NET Framework 4.6.x) — systemic issue.
- **MEDIUM**: host-header, missing headers, verbose errors, weak password
  policy, **single** out-of-support library inside a supported runtime.
- **LOW**: hardening with minor impact.
- **INFO**: observations only.

If you're tempted to change these ranks, update **all three** prompts
(security, confirmation, dependency) together. The rubric is duplicated
on purpose — each prompt has to anchor to the same scale every run.

## Category vocabulary

Pinned in the prompts. Don't invent new values:

`Injection`, `AuthN`, `AuthZ`, `Crypto`, `Secrets`, `Session`, `Config`,
`Dependency`, `Logging`, `Validation`, `Other`.

Dependency-audit findings always use `Dependency`.

## SCA (Phase 1 ground-truth CVE injection)

`scanner/sca.py` runs Google's `osv-scanner` from the host (outside the
opencode jail) against the project tree, then injects the resulting
JSON into the dependency-prompt via `{{SCA_RESULTS}}`. Locked decisions
(see plan file): SCA-as-context (LLM still produces findings, with an
explicit non-applies note for any advisory it doesn't surface),
stamped-degrade (`metadata.sca` block in JSON, italic `_SCA: ..._`
line under MD Summary), **auto-refresh during scans by default** (a
missing or >7-day-old DB triggers `refresh_offline_db` inline before
Phase 1 reads it; users opt out via `--no-auto-refresh-osv-db` /
`SCAN_NO_AUTO_REFRESH_OSV_DB=1` for cron-driven or air-gapped setups),
auto-downloaded binary pinned + sha256-verified, every supported
ecosystem refreshed unconditionally.

Auto-refresh contract (`_run_sca` in `scanner/cli.py`):

- DB missing/stale + auto-refresh enabled → log `[SCA] OSV DB missing
  — auto-refreshing now …` (mentions the size hit on first run), call
  `sca.refresh_offline_db`, then proceed. Failure falls through to
  `metadata.sca.reason = "refresh_failed"` (stamped-degrade).
- DB missing/stale + auto-refresh disabled → existing behaviour:
  `db_missing` / `db_stale` reason, no refresh, scan continues
  degraded.

The auto-refresh is always-on by default to make first-time setup a
single command (`python security-scan.py /path/to/project` works,
no separate `--refresh-osv-db` step needed). Don't change the default
to opt-in without updating README §5, the `.env` block for
`SCAN_NO_AUTO_REFRESH_OSV_DB`, and the `_run_sca` integration tests
(`test_missing_db_triggers_auto_refresh_by_default`,
`test_failed_auto_refresh_falls_through_to_degraded`).

Cache layout:

- Binary: `./.security-scan-cache/bin/osv-scanner-v<pinned>` (override
  via `SCAN_OSV_SCANNER_BIN`). Cache lives next to `security-scan.py`
  and is gitignored — same project-local pattern as `.ruff_cache/` /
  `.mypy_cache/`. Older runs put this under `~/.cache/security-scan/`;
  delete that directory after upgrading.
- Database: `./.security-scan-cache/osv/` (override via
  `SCAN_OSV_DB_DIR`). Sentinel: `.last_refresh` mtime; >7 days old =
  treated as unavailable (`reason: db_stale`).

Bumping `_OSV_SCANNER_VERSION`:

1. Pick a release: `gh release view --repo google/osv-scanner --json tagName,assets`.
2. Copy each platform's sha256 from `assets[*].digest` (strip the
   `sha256:` prefix) into `_OSV_SCANNER_SHA256`. Five entries:
   darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64.
3. Bump `_OSV_SCANNER_VERSION`.
4. Run `python3 -m unittest tests.test_security_scan -v`. The
   `ScaEnsureBinaryTests` exercise download → sha256-verify → atomic
   install with the new constants.
5. Optionally smoke-test end-to-end: `python3 security-scan.py
   --refresh-osv-db` then a real scan against `input/`.

The `[SCA]` log lines are always-on (no flag gates them), parallel
to chatlogs. `--skip-sca` / `SCAN_SKIP_SCA` records
`reason: skipped_via_flag` in `metadata.sca` so the report still
tells the truth.

If you change the osv-scanner CLI invocation in `run_osv_scan` /
`refresh_offline_db` (e.g. when bumping major versions), check the
mocked-subprocess tests still match the flag set you're passing.

`metadata.sca` carries one of three logical states:

- **Available + matches** — `available: true`, `advisory_match_count > 0`,
  `reason: null`.
- **Available + `no_sources: true`** — osv-scanner ran successfully but
  the project has no manifests in formats it extracts (pure scripts,
  custom build systems, .NET projects with `packages.config` only,
  ecosystems osv-scanner doesn't index). This is **not a degraded
  state** — the report renders a neutral "no manifests recognised"
  note. Triggered by exit code 128 OR `"No package sources found"` in
  stderr (we match both because v2 osv-scanner sometimes returns 0
  with an empty result set when run via certain frontends).
- **Unavailable** — `available: false`, `reason: db_missing | db_stale
  | binary_unavailable | nonzero_exit | parse_failure | timeout |
  skipped_via_flag`. Phase 1 runs on model-knowledge only and the
  report stamps the dep overview with the reason.

The `_run_sca` helper in `scanner/cli.py` is the single place that
coalesces these into the `metadata.sca` dict. Don't add new states
without also updating `_render_sca_state` (in `scanner/report.py`),
the dep-overview no-findings branch (also in `report.py`), and the
relevant tests (`ScaPreludeIntegrationTests`,
`ScaReportRenderingTests`).

The osv-scanner CLI flag for path exclusion in v2 is
`--experimental-exclude` (NOT `--paths-to-ignore` — that's v1 syntax,
and using it produces an "Incorrect Usage: flag provided but not
defined" error with exit 127). The same applies to refresh: it
synthesises one minimal lockfile per ecosystem in a tempdir
(`_write_ecosystem_stubs`) so `--download-offline-databases` actually
pulls every ecosystem; otherwise osv-scanner only fetches DBs for
manifests it sees.

## Manifests (Phase 1)

Handled by `_is_manifest` + `collect_manifest_contents`. Covers:

- **.NET**: `.csproj`, `.fsproj`, `.vbproj`, `.sln`, `*.config`,
  `Directory.Build.props/targets`, `Directory.Packages.props`,
  `global.json`, `nuget.config`, `packages.lock.json`.
- **Python**: `requirements.txt`, `requirements-*.txt`, `constraints.txt`,
  `setup.py`, `setup.cfg`, `Pipfile`, `pyproject.toml`, `poetry.lock`.
- **Node/Go/Rust/Java/Ruby**: standard manifests.

Files >150 KB are soft-truncated with a marker; not dropped. If the user
reports a missed outdated-lib issue, first suspect is that the manifest
collection didn't see the file — check `_is_manifest` before adjusting
the prompt.

## Cross-file context and the scanner agent

Every opencode call runs as the **`scanner` agent** defined in
`./opencode.json` at the repo root. The agent is a deliberate jail:

- **Allowed:** `read`, `grep`, `glob`, `list`, `codesearch` — anywhere
  under `--dir <project_dir>`.
- **Denied:** `bash`, `edit`, `write`, `patch`, `task` (subagents),
  `skill`, `webfetch`, `websearch`, `external_directory`.

The model can therefore traverse the project freely — follow imports,
read helpers, grep for patterns — but it cannot escape the project
root, run shell, modify files, or make outbound network calls. The
prompts (security-prompt, confirmation-prompt) tell the model to use
this freedom.

`scanner/opencode_client.py:call_opencode` passes `--agent scanner` and
`--dangerously-skip-permissions`. The "dangerous" flag only auto-approves
`allow`/`ask` rules; the agent's `deny` rules still hard-block. It also
sets `cwd=<repo_root>` on `subprocess.run` so opencode finds
`./opencode.json` regardless of where the user invokes from.

- **Monorepos:** put Web + Core under a single root, point the scanner
  at that root. The model traverses across slns as needed.
- **Multi-dir mode** (`python security-scan.py a b`) runs a and b as
  *isolated* scans. The model reviewing `a` cannot see files under `b`.
  Use multi-dir for batching unrelated projects, not cross-references.

This is enforced by opencode, not the OS. For shared-host defense in
depth, wrap the call in `sandbox-exec` (macOS) or `bwrap` (Linux) with
`<project_dir>` mounted read-only and no network.

If you change `./opencode.json`, run `opencode agent list` to confirm
the `scanner` agent is picked up — the file is loaded from `cwd`'s
nearest ancestor, which is why we set `cwd=_REPO_ROOT`.

## Dedup internals — don't simplify without testing

`_dedupe_findings` (deterministic) must NOT merge:

- findings in different files
- findings with distant line ranges (`_ranges_near` uses ±3 slack)
- titles that don't pass `_titles_equivalent` (equal-after-normalise OR
  prefix match where shorter is ≥6 chars AND ≥70% of the longer)

Test coverage lives in `tests/test_security_scan.py` under
`DedupHelpersTests`, `DeterministicDedupTests`, `SemanticDedupTests`.
If you change any heuristic threshold, update those tests too.

The semantic pass mocks `call_opencode_json` — keep it that way, no
network in the test suite.

## Output / JSON schema

`vulnerabilities.json`:
```json
{
  "metadata": {...},
  "project_brief": {...},
  "findings": [
    {
      "phase": "Per-File Review" | "Dependency Audit",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "...",
      "file": "...",
      "line": "42 or 42-48 or \"\"",
      "category": "...",            // pinned vocabulary
      "description": "...",
      "evidence": "...",
      "recommendation": "...",
      "test_steps": "...",
      "dependency": "...",          // Phase 1 only
      "confidence": "confirmed|likely|false_positive",
      "confirmation_note": "...",
      "aliases": ["..."],           // titles collapsed by dedup
      "dropped": false              // true = false positive
    }
  ]
}
```

The MD report layout (`scanner/report.py:write_markdown_report`):

1. `## Scan Summary` — single side-by-side severity table
   (`Source Code Findings | Vulnerable Dependencies` columns) and the
   `### Management Summary` paragraph from the LLM. No trailing
   confirmed/likely/dropped totals or success-state SCA stamp here —
   they were verbose and removed.
2. `---`
3. `## Source Code Findings — Overview` — the per-file fix list.
4. `## Vulnerable Dependencies — Overview` — same shape, different
   columns (`# | Sev | Dependency | Title | What to do`). Rendered
   adjacent to the source overview so a reader sees both at once.
   Degraded-state SCA stamp (`_SCA: unavailable (...)_`) appears
   *only* here when SCA failed; success state is silent.
5. `---`
6. `## Source Code Findings — Detail` — full per-finding blocks with
   anchors `f1-…`, `f2-…`.
7. `---`
8. `## Vulnerable Dependencies — Detail` — full dep blocks with
   anchors `d1-…`, `d2-…`. Each block tags the source: "osv-scanner
   advisory match (deterministic)".
9. `---`
10. `## Source Code Findings — By File` — secondary grouped view
    (only present if there are per-file findings).
11. `---`
12. `## Project Brief` — Phase 0 output.
13. `## Dropped (false positives)` — auditability tail.

Aliases render as `_Also reported as: X_` under each detail block.
Don't reorder these sections without updating the four
layout-anchored tests in `tests/test_security_scan.py`
(`test_dependency_findings_rendered_in_separate_section`,
`test_horizontal_rule_separators_between_major_sections`,
`test_no_dependency_findings_renders_empty_section`,
`test_write_markdown_report_places_business_summary_under_summary`).

The dep overview rendering reflects the three `metadata.sca` states
documented in the SCA section above (silent / neutral no-sources note /
italic degraded stamp).

## Tests

```bash
python3 -m unittest tests.test_security_scan -v
```

152 tests, ~8 s wall clock (the scan_project integration test
exercises ThreadPoolExecutor and dominates the runtime; the rest run
in ~0.5 s). All LLM calls and `osv-scanner` subprocess invocations
are mocked — no network, no external binary needed.

Coverage with `coverage`:

```bash
coverage run --source=scanner -m unittest tests.test_security_scan
coverage report
```

Target: ≥90% line coverage across `scanner/`. Current run sits at
~91%. The unmissed lines are mostly:

- `cli.py` deep error-handling paths (e.g. KeyboardInterrupt
  inside `scan_project`, prompt-template missing fallbacks).
- `opencode_client.py` retry/backoff inner loop (the rate-limit
  regex match → backoff → retry path is timing-sensitive).
- `sca.py` rare branches (download partial-file cleanup, atomic
  rename failure, timeout-during-refresh chatlog write).

Don't drop coverage by adding new code paths without tests. The
suite is fast precisely because it mocks aggressively — keep that
property.

## Linting

The `venv/` in this repo already has `ruff`, `mypy`, and `vulture`
installed. Run all three before handing work over:

```bash
source venv/bin/activate
ruff check security-scan.py
mypy --ignore-missing-imports security-scan.py
vulture security-scan.py --min-confidence 70
```

All three should be clean. `vulture` at confidence ≥70 catches genuinely
unused symbols without false-positives on framework hooks. If a warning
is a true intentional discard (a tuple-unpack throwaway), prefix the
name with `_`.

Add tests for any new helper; the dedup helpers especially are
load-bearing.

## Things not to do

- Don't shell out to `opencode` directly — route through
  `call_opencode` / `call_opencode_json` (uniform stderr / timeout /
  retry / chatlog handling).
- Don't move the prompt back onto `opencode run`'s argv. The
  business-summary phase embeds every kept finding and exceeds
  ARG_MAX (~128 KB) on Linux. `call_opencode` pipes via stdin
  (`subprocess.run(..., input=prompt)`); opencode reads from stdin
  when no positional `[message..]` arg is given.
- Don't hardcode severities or categories in Python — the rubric lives
  in prompts. Code/prompt drift produces inconsistent verdicts.
- Don't bypass `flush_reports` — single sink that dedupes before either
  artifact is written.
- Don't weaken the default-input-dir emptiness check in `main()`.
- Don't accept `input/feedback/*.md` from untrusted sources (it can
  downgrade or drop findings — see "Developer feedback" section).

## Chatlogs and retry

Every `call_opencode` invocation writes a log file to
`<output>/<timestamp>/chatlogs/NNNNN_<phase>_<tid>[_retryN].log`. Set
once per project from `cli.py:scan_project` via
`set_chatlog_dir(md_path.parent / "chatlogs")`. Always on — there is
deliberately no flag/env to turn it off (predictable artifact set).

Each phase passes its own tag through `call_opencode_json(..., phase=...)`:
`discovery`, `dependency`, `perfile`, `confirm`, `dedup`, `summary`. JSON
parse-retries are tagged `<phase>-parse-retry`.

Retry policy in `call_opencode` is deliberately narrow. opencode hangs
rather than exits on provider 429s
([sst/opencode#8203](https://github.com/sst/opencode/issues/8203)), so
the subprocess timeout is the only signal we get. With `--print-logs
--log-level INFO` opencode emits the 429 line into stderr before
hanging. We pattern-match the partial stderr on `TimeoutExpired` against
`_RATE_LIMIT_RE` (`429` / `rate limit` / `too many requests` /
`quota exceeded`) and only retry when it matches. Retries: up to
`_RETRY_ATTEMPTS=2` extra attempts (3 total) with `5 * 2**attempt`-second
backoff. Each attempt writes its own chatlog (`_retry1.log`,
`_retry2.log`).

Plain timeouts without rate-limit markers are **not** retried — they
might be slow legitimate calls or unknown hangs, and retrying just
doubles the wall clock. Nonzero exits are **not** retried either —
auth failures, bad model slugs, deny-rule trips, malformed prompts
won't fix themselves on a second attempt.

If the rate-limit regex stops matching (opencode log format change),
we silently stop retrying real 429s — pre-flight test after upgrades:
trigger a 429 once, grep `output/*/chatlogs/*.log` for the marker.

Don't gate chatlog writes on a flag. If a write fails (`OSError`), it's
swallowed — logging must never break a scan.

## Known sharp edges

- opencode's output has log prefixes (`→ ✓ ● │ …`) stripped by
  `extract_model_output`. If opencode's output format changes, `extract_json`
  starts failing silently and the retry nudge kicks in. Symptom: lots of
  `SCAN_PARSE_FAILURE` findings.
- The `confirmation_note` field is also used to surface dedup reasons
  (prefixed with `dedup:`). Don't rely on it being a single concern.
- Rate limits: default is 10 parallel calls. Drop to 5 with `--parallel 5`
  if Azure returns 429s on smaller deployments.
