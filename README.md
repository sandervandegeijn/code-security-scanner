# Agentic Security Scanner

A white-box SAST scanner that drives [opencode](https://opencode.ai)
against a project and produces a developer-oriented Markdown report
plus a machine-readable JSON artifact.

The model is given the target file **plus jailed filesystem access** —
it can read related code (callers, middleware, helpers, config) inside
the project root, and nothing outside. Every finding is then put
through a confirmation pass that re-reads the cited code and either
upgrades, downgrades, or drops it.

---

## Setup — opencode is the foundation

This whole tool is a thin Python wrapper around `opencode run`. If
opencode isn't installed and authenticated against an LLM provider, the
scanner has nothing to drive. Get this right before anything else.

### 1. Install opencode

```bash
# macOS
brew install sst/tap/opencode

# verify
opencode --version
```

Other platforms: see <https://opencode.ai/docs/install>.

### 2. Wire opencode to an LLM provider

The scanner defaults to `azure/gpt-5.5`. To use that, configure Azure
AI Foundry as a provider in your **user-level** opencode config:

`~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "azure": {
      "npm": "@ai-sdk/azure",
      "name": "Azure AI Foundry",
      "options": {
        "baseURL": "https://<your-resource>.cognitiveservices.azure.com/openai",
        "apiKey": "<your-azure-key>",
        "apiVersion": "preview"
      },
      "models": {
        "gpt-5.5":      { "name": "GPT-5.5" },
        "gpt-5.4-mini": { "name": "GPT-5.4 Mini" },
        "gpt-5.3-codex":{ "name": "GPT-5.3 Codex" }
      }
    }
  }
}
```

Each entry under `"models"` is the **deployment name** in Azure (not
the underlying base model). List only deployments that actually exist
in your Azure resource. The `apiVersion: "preview"` value targets
opencode's `@ai-sdk/azure` URL shape (`/openai/v1/responses?api-version=preview`).

Don't want Azure? Any opencode-supported provider works:

```bash
opencode auth login            # GitHub Copilot, OpenAI OAuth, etc.
opencode auth list             # see what's configured
opencode models                # see available provider/deployment slugs
```

Pick a different default by editing `.env` (`SCAN_MODEL=...`) or
overriding per-run with `--model`.

Sanity check end-to-end:

```bash
opencode run --model azure/gpt-5.5 "say hi"
```

### 3. The `scanner` agent (security jail)

This repo ships a project-level `opencode.json` defining a custom
**`scanner` agent** that opencode runs every per-file call under. It
is a deliberate read-only jail:

- **Allowed:** `read`, `grep`, `glob`, `list`, `codesearch` — anywhere
  under the scan target's `--dir`.
- **Denied:** `bash`, `edit`, `write`, `patch`, `task` (subagents),
  `skill`, `webfetch`, `websearch`, `external_directory`.

The model can therefore traverse the project freely (follow imports,
read helpers, grep for patterns) but cannot escape the project root,
run shell, modify files, or make outbound network calls.

The scanner verifies the agent is registered at startup (calls
`opencode agent list`) and refuses to run if not — a missing agent
combined with `--dangerously-skip-permissions` would turn the default
agent's `ask` rules into effective `allow`, breaking the jail. To
inspect:

```bash
OPENCODE_CONFIG=$(pwd)/opencode.json opencode agent list | grep -A1 '^scanner'
```

`OPENCODE_CONFIG` is an explicit override the scanner sets internally
because opencode's normal "walk up to nearest .git" config discovery
short-circuits when the scan target is itself a git repo (which it
usually is).

### 4. Python prerequisites

```bash
python3 --version              # 3.10+
python3 -m venv venv && source venv/bin/activate
pip install ruff mypy vulture  # for development; runtime has no deps
```

The runtime itself has zero PyPI dependencies — only the standard
library plus the `opencode` CLI.

### 5. OSV database (auto-refreshing by default)

Phase 1 (dependency audit) is augmented with **ground-truth CVE data**
from a locally cached OSV/GHSA snapshot via Google's `osv-scanner`. The
LLM still does the reasoning (exploitability, severity, project context),
but version-range matching is delegated to osv-scanner so the report is
not bounded by the model's training cutoff.

The scanner downloads `osv-scanner` itself on first use (pinned version,
sha256-verified, cached under `./.security-scan-cache/bin/` next to
`security-scan.py` — gitignored, same project-local pattern as
`.ruff_cache/` / `.mypy_cache/`), so there is no separate install step.

**By default the OSV/GHSA database also auto-refreshes during scans**
when it's missing or older than 7 days. The first scan after install
will pull ~1.5–2 GB and may take several minutes — the scanner prints
a clear `[SCA] OSV DB missing — auto-refreshing now…` line before the
download starts. Subsequent refreshes are incremental and small.

If you prefer to manage refreshes yourself (cron, CI, air-gapped),
disable the auto-refresh and run the explicit command on your
schedule:

```bash
# Disable auto-refresh: pass --no-auto-refresh-osv-db on every run, or
# set SCAN_NO_AUTO_REFRESH_OSV_DB=1 in .env.

# Then refresh on your own schedule:
python3 security-scan.py --refresh-osv-db
```

Recommended cron entry — daily refresh at 06:00:

```
0 6 * * * cd /path/to/security-scan && python3 security-scan.py --refresh-osv-db >> /tmp/osv-refresh.log 2>&1
```

If auto-refresh is disabled and the database is missing, stale
(>7 days), or osv-scanner cannot run for any reason, the scan still
completes — the report is **stamped**
(`metadata.sca` block in the JSON, italic `SCA: …` line under the
Markdown Summary) so triagers can tell whether "no Phase 1 CVEs" means
"verified clean" or "we couldn't check".

#### Manual install / air-gapped environments

If GitHub Releases is unreachable on the scanning host (corp egress
policy, air gap, etc.), install `osv-scanner` yourself and point the
scanner at it via the `SCAN_OSV_SCANNER_BIN` env var or the matching
`.env` setting:

```bash
# macOS via Homebrew
brew install osv-scanner

# Linux: grab the v2 binary from your internal mirror, or build from
# source — https://github.com/google/osv-scanner
# Then expose it to the scanner:
export SCAN_OSV_SCANNER_BIN=/usr/local/bin/osv-scanner
```

The DB refresh still uses the same offline-mode flag set, so once the
binary path is set the `--refresh-osv-db` command works as before.
The scanner enforces the pinned version against `_OSV_SCANNER_SHA256`
only on the *auto-downloaded* path; user-provided binaries are trusted
verbatim.

---

## Usage

### 1. Drop the code to scan into `input/`

```bash
git clone --depth 1 https://github.com/snyk-labs/nodejs-goof.git input/nodejs-goof
# or symlink:
ln -s /path/to/my-app input/my-app
```

The default target is the `input/` directory itself. You can put a
single project there directly, or multiple subdirectories and scan
those explicitly.

```
input/
  SECURITY_SCAN.md  <- optional developer guidance for the scanner
  <project files...>
```

For multi-project mode, pass paths positionally:
`python3 security-scan.py /path/to/projA /path/to/projB`

### 2. Run

```bash
# Default: scans ./input, writes ./output/<YYYY-MM-DD_HH-MM>/vulnerabilities.{md,json}
python3 security-scan.py

# Explicit project, still timestamped under ./output/
python3 security-scan.py /path/to/project

# Multiple projects → one subdir per project under the timestamp dir
python3 security-scan.py /path/to/projA /path/to/projB

# Preview which files will be scanned (no AI calls):
python3 security-scan.py --dry-run /path/to/project

# Dependency audit only (fast sanity pass)
python3 security-scan.py --dependencies-only /path/to/project
```

### 3. Read the report

```bash
open output/<timestamp>/vulnerabilities.md
jq '.findings[] | select(.severity=="CRITICAL" and .dropped==false)' \
   output/<timestamp>/vulnerabilities.json
```

`--output <path>` honours your path literally (no timestamp injection)
when you need reproducible artifact paths.

---

## Project context and developer feedback (`<project-root>/SECURITY_SCAN.md`)

Create one file named `SECURITY_SCAN.md` at the root of the project
being scanned. Its contents are injected into the per-file, dependency-
audit, and confirmation prompts so the model treats them as
authoritative context.

Start from [`SECURITY_SCAN.template.md`](SECURITY_SCAN.template.md).
The template asks for the project details the scanner cannot infer from
source code: hosting model, whether the tool is public or internal-only,
authentication method, likelihood context such as required privileges and
exploit maturity, data/damage classification, compensating controls,
monitoring, vulnerability age, and risk-acceptance context. This context
is especially important for the final product-owner summary, which uses
the included vulnerability handling standard to explain likely business impact
and remediation urgency.

Use it for:

- **Whitelisting** intentional findings — "the hardcoded `root/root`
  MySQL credential in `typeorm-db.js` is a docker-compose seed; treat
  as false positive."
- **Documenting upstream mitigations** the code can't show — "the
  load balancer rewrites the host header before reaching the app, so
  reset-link-poisoning findings are not exploitable."
- **Recording risk acceptance** — "we run on .NET Framework 4.6 until
  Q3 2026; do not flag as CRITICAL, the timeline is in JIRA-1234."
- **Pointing at non-obvious helpers** — "all SQL goes through
  `Helpers/SafeQuery.cs::Run` (parameterised). Findings of raw
  `SqlCommand` outside that helper are real."

The last section in the template is **Developer Feedback on Scanner
Findings**. Keep it last so future scan comments can be appended without
moving the stable project-context sections.

Confirmation-pass behaviour: a finding the feedback marks as
intentional/accepted comes back with `confidence: false_positive` and
lands in the dropped table. A partial mitigation comes back with a
downgraded `severity_override` and a `confirmation_note` that cites
the feedback file by name.

**Trust model** — this file is treated as authoritative, so only
the team running the scan should write here. Do not accept feedback
contributions from external or untrusted sources; a malicious file
could prompt-inject the model into ignoring real vulnerabilities.

**Resolution order** (first match wins):

1. `--feedback-dir` / `SCAN_FEEDBACK_DIR` (file path or a directory containing `SECURITY_SCAN.md`).
2. `<project_dir>/SECURITY_SCAN.md`.
3. If exactly one immediate visible subdirectory of `<project_dir>` contains a `SECURITY_SCAN.md`, that file is used. Two or more matches → the scanner refuses to guess and logs all candidates so you can pass the correct subdir or `--feedback-dir` explicitly.

Every run prints exactly one `[Feedback]` line at startup so you can see what was loaded (or why nothing was).

---

## Configuration via `.env`

Most settings live in `./.env` next to `security-scan.py`. Each
setting is documented inline in that file. Edit it instead of
memorising flags.

Precedence (highest wins):

1. **CLI flag** (`--parallel 5`)
2. **Real OS environment variable** (`SCAN_PARALLEL=5 python …`)
3. **`.env` value**
4. **Hardcoded fallback** in `scanner/config.py`

Per-invocation things stay CLI-only: `project_dirs`, `--output`,
`--prompt-dir`, `--dry-run`, `--dependencies-only`. They have no
`.env` equivalent on purpose — they vary every run.

Settings backed by `.env`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCAN_MODEL` | `azure/gpt-5.5` | opencode model slug. |
| `SCAN_PARALLEL` | `10` | Max concurrent opencode calls. |
| `SCAN_TIMEOUT` | `300` | Seconds per call (Phase 0/1 use 2x). |
| `SCAN_MAX_FILE_SIZE` | `100000` | Skip per-file scans above this (bytes). |
| `SCAN_EXTENSIONS` | (built-in) | Comma-separated source extensions. |
| `SCAN_EXCLUDE_DIRS` | (none) | Extra directory basenames to prune. |
| `SCAN_SKIP_DISCOVERY` | off | Skip Phase 0. |
| `SCAN_SKIP_DEPENDENCIES` | off | Skip Phase 1. |
| `SCAN_SKIP_CONFIRMATION` | off | Skip the confirmation pass. |
| `SCAN_SKIP_DEDUP` | off | Skip the semantic dedup pass. |
| `SCAN_SKIP_SCA` | off | Skip osv-scanner ground-truth CVE injection in Phase 1. |
| `SCAN_OSV_DB_DIR` | `./.security-scan-cache/osv/` | Local OSV/GHSA database directory (project-local, gitignored). |
| `SCAN_OSV_SCANNER_BIN` | (auto-download) | Override the pinned osv-scanner binary path. |
| `SCAN_NO_AUTO_REFRESH_OSV_DB` | off | Disable auto-refresh of the OSV DB during scans. Default behaviour: a missing or >7-day-old DB triggers an automatic refresh before Phase 1 reads it. |

---

## How the scanner works

Six phases. LLM phases talk through `opencode run`, which gives the
model live filesystem access (jailed by the `scanner` agent) to the
project it's scanning.

1. **Phase 0 — Discovery.** One call. Produces a JSON project brief
   (stack, entry points, auth, trust boundaries, shared helpers,
   config/secret locations, notable risks). Reused as context by
   every later call in the same scan run.
2. **Phase 1 — Dependency audit.** One call. The host first runs
   `osv-scanner` against the project (offline, against a locally
   cached OSV/GHSA snapshot — see Setup §5) and feeds the resulting
   ground-truth CVE matches into the prompt. The LLM then reads all
   manifests (`package.json`, `requirements.txt`, `*.csproj`,
   `Cargo.toml`, `Dockerfile`, etc.) plus the SCA block, flags known
   CVEs, EOL runtimes, outdated packages, risky patterns, vendored
   binaries. When osv-scanner is unavailable the report is stamped
   (`metadata.sca`) so triagers can tell.
3. **Phase 2 — Per-file review.** One call per source file, in
   parallel up to `SCAN_PARALLEL`. The prompt contains the project
   brief, a directory tree of scanned files, and the inlined target
   file. The model opens related files (callers, helpers, config)
   before deciding whether each finding is real.
4. **Confirmation pass.** Every finding is re-verified independently.
   The model re-reads the cited code, returns
   `confirmed`/`likely`/`false_positive`, and may emit a
   `severity_override` (e.g. MEDIUM → CRITICAL when it discovers a
   hardcoded prod credential). False positives are dropped from the
   main report but retained in JSON with `"dropped": true`.
5. **Semantic dedup pass.** Per-file LLM call clustering findings
   that describe the same root cause under different titles
   (e.g. `SQL_INJECTION_IN_QUERY` and `UNSANITIZED_SQL_INPUT` at the
   same lines). Canonical title wins, dropped titles become `aliases`.
6. **Business summary.** One final LLM call after confirmation and
   dedup. It receives the final findings, the project brief,
   `SECURITY_SCAN.md`, and
   `prompts/context/vulnerability-handling-standard.md`. It returns
   only a concise product-owner summary for the report `## Summary`;
   it does not change findings, severities, confidence, or dropped
   status.

Both reports are flushed to disk after every completed unit, so
Ctrl-C leaves a valid partial artifact. The business summary is only
added during the final flush.

### Chatlogs

Every opencode invocation writes a per-call log to
`output/<timestamp>/chatlogs/NNNNN_<phase>_<tid>.log`, containing the
prompt, full stdout, full stderr, return code, and wall time. This is
always on — runs produce a stable artifact set. To answer questions
like "did we hit 429s?" after the fact:

```bash
grep -li "429\|rate" output/<timestamp>/chatlogs/*.log
grep -l  "timeout"   output/<timestamp>/chatlogs/*.log
```

opencode hangs (does not exit) on provider rate-limit errors
(see [sst/opencode#8203](https://github.com/sst/opencode/issues/8203)),
so the scanner's per-call subprocess timeout is what eventually
unblocks the scan. opencode is invoked with `--print-logs --log-level
INFO` so the provider's 429 line lands in the captured stderr before
opencode hangs.

Retry policy is conservative:

- **Timeout with `429` / `rate limit` / `too many requests` in stderr** —
  retried up to 2× with 5 s and 10 s backoff. Retry attempts produce
  `*_retry1.log` / `*_retry2.log` files.
- **Timeout without those markers** — returned as an error, no retry.
  Could be a slow legitimate response or an unknown hang; retrying
  doubles the wall clock without any reason to expect a different
  result.
- **Nonzero exit** — returned as an error, no retry. Auth failure,
  bad model slug, agent deny-rule trip etc. won't fix themselves on a
  second attempt.

A typical run produces tens of MB of chatlogs. They're safe to delete
after triage.

---

## Reading the report

### Severity

| Severity | Meaning |
| --- | --- |
| 🟣 CRITICAL | Pre-auth RCE, auth bypass, hardcoded prod secrets in source, unauthenticated admin/reset endpoints. |
| 🔴 HIGH | Authenticated RCE, injection behind auth, weak crypto in session/reset tokens, EOL runtime/framework targeted by the project. |
| 🟠 MEDIUM | Host-header issues, missing security headers, weak password policy, single out-of-support library. |
| 🟡 LOW | Hardening with minor impact. |
| ⚪ INFO | Observation, no direct security impact. |

### Confidence

| Confidence | Meaning |
| --- | --- |
| `confirmed` | Confirmation pass reproduced the issue by re-reading the code. Trust these. |
| `likely` | Risky pattern, exploitability not fully verified. Triage with judgement. |
| `false_positive` | Verified wrong; dropped from the main report (kept in JSON for audit). |

### Markdown layout

1. **Summary** — severity and confidence counts plus the final business-readable summary.
2. **Findings — fix from top to bottom** — flat severity-sorted table, one-line fix per row.
3. **Detail** — per-finding sections with location, evidence, recommendation, verify steps, mitigations considered, confirmation note.
4. **Findings by File** — by-file view for when you're already in a file and want to address everything there.
5. **Project Brief** — stack, auth, trust boundaries, shared helpers, config/secrets.
6. **Dropped (false positives)** — auditability table.

---

## Directory layout

```
security-scan.py            entry point (~80 lines, re-exports for tests)
scanner/                    package — config, discovery, opencode_client,
                              prompts, findings, confirmation, perfile,
                              dedup, report, cli
opencode.json               scanner-agent jail definition (committed)
.env                        runtime configuration (committed; no secrets)
prompts/
  discovery-prompt.md       Phase 0
  dependency-prompt.md      Phase 1
  security-prompt.md        Phase 2 (per-file)
  confirmation-prompt.md    confirmation pass
  dedup-prompt.md           semantic dedup
  summary-prompt.md         final business summary
  context/
    vulnerability-handling-standard.md
                            handling-standard context for summary
input/                      default scan target (gitignored except .gitkeep)
output/                     reports under <timestamp>/ subdirs
tests/test_security_scan.py unittest tests (mocked, ~0.5 s)
CLAUDE.md                   guidance for future Claude sessions
```

---

## Troubleshooting

**`'opencode' not found on PATH`** — install opencode and make sure
`which opencode` succeeds in the shell you launch the scanner from.

**`FATAL: the 'scanner' agent is not registered with opencode`** — the
project-level `opencode.json` was not picked up. Verify the file
exists at the repo root and run `OPENCODE_CONFIG=$(pwd)/opencode.json
opencode agent list | grep ^scanner` to confirm.

**Permission `ask` blocking the scan** — should not happen given the
jail. If it does, the agent definition didn't load (see above) and
the default `build` agent is being used instead.

**Scan is slow.** Each file is one call; confirmation doubles that;
dedup adds a per-file LLM call where ≥2 findings exist. Options:
raise `SCAN_PARALLEL`, switch to a cheaper model
(`SCAN_MODEL=azure/gpt-5.4-mini`), set `SCAN_SKIP_CONFIRMATION=1` for
a fast first pass, or narrow with `SCAN_EXTENSIONS`.

**Timeouts.** Raise `SCAN_TIMEOUT`. Phase 0 and Phase 1 use 2x
automatically.

**Parse failures.** A scan call that returns un-parseable output
after one retry produces a synthetic `SCAN_PARSE_FAILURE` finding so
the run continues. The file path is recorded; re-run that one file
in isolation.

**Interrupt safety.** Ctrl-C at any point leaves a valid `.md` and
`.json` covering everything completed so far.

---

## Development

```bash
# Tests
python3 -m unittest tests.test_security_scan

# Lint (must be clean before commit)
source venv/bin/activate
ruff check security-scan.py scanner/
mypy --ignore-missing-imports security-scan.py scanner/
vulture scanner/ security-scan.py --min-confidence 70
```

Tests mock all `opencode` calls and run in ~0.5 s. The scanner-agent
pre-flight is mocked in `MainDispatchTests.setUp()` to keep the suite
hermetic.

See `CLAUDE.md` for deeper architectural notes (prompt-cache
invariants, dedup heuristic thresholds, multi-dir mode quirks).
