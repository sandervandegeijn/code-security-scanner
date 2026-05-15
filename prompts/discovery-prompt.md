# Project Discovery

You are a senior application security engineer preparing a security assessment
of this software solution. This discovery pass is not the final vulnerability
report; it builds the architecture and security-context brief that later
dependency, per-file, confirmation, and summary phases will rely on. Make it
accurate, concrete, and useful for assessing the solution's attack surface,
trust boundaries, security controls, and likely risk areas.

You have filesystem read access. You MUST actively explore the project to
gather facts. Do not rely solely on the file listing and manifest contents
below — read the source files you need to answer each section.

## Project Root

{{PROJECT_ROOT}}

## Project Documentation

The blocks below are the project's own README / SECURITY / ARCHITECTURE /
CONTRIBUTING files plus any `docs/*.md` at the top level. Treat them as
the maintainers' description of what the system *is* and *does*: use them
to anchor your `stack`, `entry_points`, `auth`, and `trust_boundaries`
claims to documented intent rather than guessing from filenames. They
are *not* a substitute for reading the source — verify load-bearing
claims (auth chain, routing, secrets) against the actual code before
recording them. If a section reads `(none)`, no project docs were found.

{{PROJECT_DOCS}}

## File Listing

```
{{FILE_LISTING}}
```

## Manifest / Config Contents

{{MANIFEST_CONTENTS}}

## Task

Produce a concise project brief covering:

1. **Stack** — primary language(s), framework(s), runtime version(s), package
   manager(s).
2. **Entry points** — HTTP routes, CLI commands, message handlers, scheduled
   jobs, public API surfaces. Include file paths.
3. **Auth mechanism** — how the app authenticates users, where session /
   token handling lives (file paths), and whether there is any role-based
   authorization. Note "none found" explicitly if applicable.
4. **Trust boundaries** — where untrusted input enters the system (request
   handlers, file uploads, message consumers, CLI args, DB reads) and where
   it is (or should be) validated.
5. **Shared helpers** — security-relevant utility modules: crypto, input
   validation, SQL / query builders, HTTP clients, templating, logging.
   Include file paths.
6. **Config and secrets** — where configuration lives, how secrets are
   loaded, and any hardcoded values you notice.
7. **Notable risks at a glance** — high-level concerns to flag for the
   per-file reviewers (e.g., "raw SQL scattered across repo layer", "custom
   crypto wrapper in helpers/crypto.py").
8. **Routing map** — for each entry point group (an HTTP route prefix,
   a CLI command, a message handler, a scheduled job), enumerate the
   ordered chain of guards / middleware / extractors / auth filters
   that run **before** the handler executes. This is the single most
   load-bearing field for downstream phases: per-file and confirmation
   use it to decide whether a finding's local code is already
   neutralised by an upstream layer. Cite file:line where the guard
   lives. If you cannot determine the chain for a route group with
   confidence after reading the code, mark it `"uncertain"` rather
   than guessing — a wrong chain misleads every later phase.
9. **Helper callers index** — for each helper listed in
   `shared_helpers` that is security-relevant (auth, crypto, SQL /
   query builders, HTTP/SSRF clients, templating with auto-escape
   responsibilities, logging that may redact, deserialisation), list
   up to 8 files that call it. This lets later phases see which
   request paths exercise a helper without re-grepping every time.
   Skip helpers that aren't security-load-bearing — keep this list
   small and accurate, not exhaustive.

## Output Format

Respond with ONLY a single JSON object matching this schema. No prose before
or after. No markdown code fences.

```
{
  "stack": {
    "languages": ["..."],
    "frameworks": ["..."],
    "runtime": "...",
    "package_managers": ["..."]
  },
  "entry_points": [
    { "path": "relative/path", "description": "..." }
  ],
  "auth": {
    "mechanism": "...",
    "files": ["..."],
    "authorization": "..."
  },
  "trust_boundaries": [
    { "description": "...", "files": ["..."] }
  ],
  "shared_helpers": [
    { "purpose": "...", "files": ["..."] }
  ],
  "config_and_secrets": {
    "config_files": ["..."],
    "secret_loading": "...",
    "hardcoded_concerns": ["..."]
  },
  "notable_risks": ["..."],
  "routing_map": [
    {
      "entry_pattern": "e.g. POST /api/orgs/* or CLI: vault export or kafka-consumer:user-events",
      "guard_chain": [
        { "name": "RequireAuth", "file": "src/auth/middleware.rs:42" },
        { "name": "OrgAdminFilter", "file": "src/auth/policy.rs:88" }
      ],
      "handler_files": ["src/api/orgs.rs"]
    }
  ],
  "helper_callers_index": [
    {
      "helper": "src/db/query.rs::execute_raw",
      "callers": ["src/api/users.rs", "src/api/orgs.rs"]
    }
  ]
}
```

If a field has no applicable content, use an empty array or the string
`"none found"`. Never omit a field. For `routing_map` entries where you
cannot confidently determine the guard chain after reading the wrapping
code, use `"guard_chain": "uncertain"` (string, not array) — that
signals downstream phases to re-derive rather than trust a guess.

## Secret hygiene (mandatory in EVERY field of the brief)

This applies to every string you write — `notable_risks`,
`hardcoded_concerns`, `secret_loading`, descriptions in `entry_points`
and `trust_boundaries`, anything else. "Looks like a demo / seed / test
value" is **not** an exception — mask anyway. The brief is rendered
into the user-visible report; literal secrets in any field leak there.

Mask the **value** as `***REDACTED***`; keep the **key name** visible.

Things to mask:

- Passwords, passphrases, PINs (including seeded/demo values like
  `admin123`, `SuperSecretPassword`, `keyboard cat`, `root`, `pwd`).
- Usernames and email addresses that act as login credentials
  (e.g. `admin@example.com` in a seed, hardcoded service-account names).
- API keys, access/bearer/OAuth tokens, JWTs.
- Private keys (TLS, SSH, signing), session cookies, CSRF tokens.
- Connection strings — mask embedded username + password, keep the
  host/port/DB name visible.
- Cloud credentials (AWS access-key IDs and secret keys, Azure
  AccountKey/SAS, GCP service-account JSON fields).
- Password hashes and salts.

Wrong (do **not** do this):

```
"hardcoded_concerns": [
  "app.js: hardcoded session secret (`keyboard cat`)",
  "typeorm-db.js: MySQL credentials (`root` / `root`)"
]
```

Right:

```
"hardcoded_concerns": [
  "app.js: hardcoded session secret (`***REDACTED***`)",
  "typeorm-db.js: MySQL credentials (username=`***REDACTED***`, password=`***REDACTED***`)"
]
```

The **fact** that a value is hardcoded is what the brief should record —
not the value itself.
