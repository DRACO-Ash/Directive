# CLAUDE.md

Always-true conventions for this project. Procedures live in `.claude/skills/`. The house voice is in `.claude/output-styles/house-voice.md`. When a rule here and a skill disagree, this file wins for conventions and the skill wins for procedure.

## What this project is

The Bluestaq Compliance Operations Console: one authenticated system of record for Bluestaq Ltd's compliance operating rhythm, registers, incident tracking, and IASME and Defence Cyber Certification (DCC) assessor evidence, held in local files on the persistent volume and evidenced by a tamper-evident audit log. Archetype: `server` (a Flask process serves requests, authenticates against Entra ID, and mediates every write). Deployment target: the Bluestaq App Store at `comply-ops.apps.bluestaq.com`, detected template `python` (by `requirements.txt`).

**The application does not integrate with SharePoint.** It is the system of record on its own volume and produces standalone files the ISM exports and uploads by hand. Ash's decision, and it removes the Microsoft Graph client, the SharePoint list models, and the platform gateway exemption question from the build. Two consequences follow and neither is optional. AUD-001 rests its delete-and-modify control on SharePoint list versioning and ISC-Owners permission, which no longer sits in the live path, so **the export cadence is a security control rather than housekeeping**: until an export is uploaded, the volume holds the only copy of the log and its anchor. And the corroboration that would have closed the anchor's blind spot (the list holding rows while the volume holds no anchor) has to come from the uploaded export instead. See `docs/DEPLOYMENT.md`.

Authentication stays in the application, against Entra ID with MSAL, rather than being delegated to the platform gateway. Ash's decision. It keeps `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, and `REDIRECT_URI` live, and it means the audit entry's actor comes from a verified token rather than a header a caller reaching the pod directly could assert. That is what makes attribution defensible in front of an assessor, and it satisfies AMD-001 section 10.4 directly.

> Superseded by the App Store decision: the flight plan's Azure App Service target, Azure Key Vault, staging-slot deploy, Application Insights telemetry, and edge IP restriction. AUD-001's Monitoring and Alerting table names five Application Insights alerts that the App Store does not provide; the table is recorded as `TBC, re-verify` pending an AUD-001 amendment, and the gap is stated openly in `docs/DEPLOYMENT.md` rather than implied to be covered. Adam Field owns both amendments. AUD-001 and AMD-001 are otherwise binding on this build; note that the approval row of each is signed by no date yet.

## Hard rules (never violate)

● **No secrets in any shippable file**, in source or in history. Read secrets from the environment; render any value in docs as `[REDACTED:type]`. The pre-write hook blocks a credential before it lands.
● **No client-side access gate.** A hardcoded Personal Identification Number (PIN), flag, or hidden field in the browser is a User Experience gate, never security. Real gates are server-side.
● **Surgical edits only.** Change the smallest region that satisfies the request. Do not reformat, re-indent, or reconstruct regions you were not asked to touch.
● **Never invent a name, title, date, organisation, or figure** in user-facing content or data. If a fact is not verifiable, mark it with the explicit unknown marker (`TBC, re-verify`); do not assert it.
● **Every untrusted value is escaped or validated at the boundary**, and a control that cannot be verified is treated as failed (fail closed).
● **The container is the whole build.** A single `Dockerfile` installs from the hash-locked lockfile and runs the server; no separate bundler output. It runs as the non-root numeric user `10001:10001`, ships no package manager, carries no setuid or setgid bits, and is flattened to one layer.
● **Listen on `PORT`, default 8080, bound to `0.0.0.0`.** Never add `ENV PORT=` or `ENV DATA_DIR=` to the Dockerfile. Answer `/`, `/healthz`, `/health`, `/readyz`, `/livez`, and `/ping` with HTTP 200, unauthenticated, and never a redirect at the root.
● **A probe never raises and never hangs.** The storage probe converts every failure into a verdict and abandons a stalled write inside a bounded time. The diagnostics read-out is the recovery channel for a bad configuration value, so nothing in the probe path may prevent boot or block a request indefinitely.
● **Liveness never depends on a downstream.** A liveness path that probes Entra ID or the storage volume restarts a healthy container during a transient outage of either. Dependency reporting belongs on `/readyz`.
● **Every register mutation writes one chained audit entry** through `complyops.audit` per AUD-001. No code path writes a record without it.
● **The audit chain is keyed and anchored, and the chain itself is never broken.** Entries are signed with HMAC-SHA256 under a server-held key, so write access to the log is not enough to re-stamp a row. AUD-001 specifies a SHA-256 hash over timestamp, user, action and resource; this build keys that digest, extends it to the full AUD-001 field set, and chains each entry to its predecessor. Stronger than the letter of the policy on every axis, and recorded as a deviation for Adam Field's sign-off. The trusted anchor on the persistent volume is what detects a truncation or a wholesale rewrite; it is authenticated under the same key, so volume access alone cannot forge one. Verifying the whole log means `verify_log`, which takes the anchor as a required argument: `verify_sample` exists for a mid-log run and cannot detect a truncation, by construction.
● **Pruning moves entries out of the active log; it never breaks the chain.** AUD-001 retains 24 months active, exports annually to Library 08, and prunes the active list for query performance. The anchor therefore records the total entries ever written and the digest of the last pruned entry, so the chain runs unbroken across the archive boundary and the annual export carries the link. Verification of the active log alone is a `verify_sample` run starting from the archived link, never a `verify_log` run: an active log that legitimately starts mid-chain is not a truncated one. Changing `FIELD_ORDER`, the digest construction, or the chaining breaks every historical entry and is an irreversible decision requiring the Managing Director's sign-off; a golden test vector pins those three. Tightening a field cap or character rule does NOT break the digests, and is reported as `invalid_under_current_rules` rather than as tampering, but it is still one-way: an entry already written cannot be brought back inside a narrower rule.
● **Audit field values are printable ASCII, by allowlist.** A denylist over Unicode leaks: rejecting category `Cc` missed the line and paragraph separators that forge a log line, and the format characters that misrepresent an actor. A value outside the set is rejected, never transliterated, because an entry is evidence.
● **A verdict, never an exception.** Verification returns a verdict for every input including a hostile one, and reports an entry that fails today's field rules separately from a tampered one. Field rules can only tighten, so history written under looser rules must never read as tampering.
● **Audit fields are validated, capped, and rejected at the boundary, never coerced.** An entry is immutable, so an over-collected or malformed field cannot be corrected or erased later without breaking the chain. That also means a cap cannot be added after the first entry is written.
● **An audit entry records that an action happened, never what the record said.** AUD-001 asks for the old and new value of a changed field. This build records the field NAMES that changed and never their values, so an incident's content cannot reach an immutable log that no Article 17 erasure can reach either. Ash's decision, and a documented deviation from the AUD-001 data column. Where AUD-001 needs a genuine before-and-after, as it does for a task status or an incident phase, `old_state` and `new_state` carry it under a character rule that structurally cannot hold a name, an address, or an email: upper snake case, 32 characters. The rule is the guarantee, not a promise about how the fields are used.
● **The actor, source address, and user agent are deliberately collected personal data.** AUD-001 requires all three on an authentication event, and the lawful basis is legitimate interest for security monitoring per POL-002 section 03. They are not an accident to be minimised away, and this rule exists so nobody removes them believing they are a leak. No credential, no session token, and no record content ever joins them. Client errors stay generic; the detail stays server-side.

## Commands

```
.venv/bin/python -m pip install --require-hashes -r requirements.txt \
                                                 -r requirements-dev.txt   # install
sh scripts/verify.sh                                                       # the loop
.venv/bin/flask --app wsgi run --port 8080                                 # local dev
docker build -t comply-ops .                                               # build
```

Every change runs the verification loop, then passes the `engineering-reviewer` and `security-reviewer` gates before it is done. Anything that deploys, publishes, or mutates external state requires the `deploy-gate` verdict and an explicit human confirmation.

## Directory layout

```
src/complyops/          the application source (src layout: the platform scopes analysis to src)
  audit/                the chained audit log, AUD-001
  views/                one Flask blueprint per functional area
SECURITY.md             the vulnerability disclosure pointer, AMD-001 section 10.6
wsgi.py                 the container entrypoint, reads PORT
Dockerfile              the whole build
tests/                  the suite, run against the uploaded package by the platform
scripts/verify.sh       the verification loop, one command
docs/                   deployment parameters and runbooks
.claude/                this baseline (skills, agents, output style, hooks, settings)
```

## Toolchain

Python 3.12, pinned in `.python-version`. Dependencies are exact-pinned and hash-locked in `requirements.txt` and `requirements-dev.txt`, compiled from the `.in` files with `pip-compile --generate-hashes`. Lint and format with `ruff` on the platform's analyser profile, not a looser default. Types with `mypy` in strict mode across the whole package. Tests with `pytest`, coverage to Cobertura XML at `coverage.xml`, which is the exact artefact the App Store Code Quality gate reads. Dependency scanning with `pip-audit`, where an unreachable advisory service is an honest skip locally and a hard failure in Continuous Integration. Static application security testing with `bandit`, required by AMD-001 section 10.6 on every code change; `ruff` and `mypy` are a linter and a type checker and do not satisfy that clause.

## Quality bar

● Coverage at least 80% overall. This is the App Store gate's bar, and it supersedes the flight plan's 60%.
● Zero open analyser violations, because the quality gate fails on any one of them.
● A control is unfinished until a mutation shows it can fail. Measure a figure before asserting it.
● A leg that cannot run locally exits non-zero and says so. It is never reported as a pass.
● Every response carries the AMD-001 section 10.6 security headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and X-Frame-Options. Tighten only, never loosen.

## Naming and versioning

● Releases are `V2.0`, `V2.1`, and so on, held in `pyproject.toml` and surfaced by `/api/diagnostics`.
● The App Store slug is `comply-ops`: lowercase, hyphenated, a single hyphen only. A double hyphen breaks platform naming and fails the pipeline with zero stages run.
● Commit messages follow `[MODULE] short imperative summary` per AMD-001 section 10.3.

## House voice (applies to all prose, UI copy, comments, commits)

UK English throughout, in code comments, interface copy, documents, and commit messages. Ash's stated preference, recorded here so it is not re-litigated. Never fabricate data. Avoid the long em-dash; a single dash is fine. No `+` meaning "and" in prose. Use `●` for bullets, never a dash. Expand an uncommon acronym on first use. Lead with the decision, then the reasoning. Full voice: `.claude/output-styles/house-voice.md`.
