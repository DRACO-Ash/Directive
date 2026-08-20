# CLAUDE.md

Always-true conventions for this project. Procedures live in `.claude/skills/`. The house voice is in `.claude/output-styles/house-voice.md`. When a rule here and a skill disagree, this file wins for conventions and the skill wins for procedure.

## What this project is

The Bluestaq Compliance Operations Console: one authenticated system of record for Bluestaq Ltd's compliance operating rhythm, registers, incident tracking, and IASME and Defence Cyber Certification (DCC) assessor evidence, backed by SharePoint Lists and a tamper-evident audit log. Archetype: `server` (a Flask process serves requests, calls Microsoft Graph, and mediates every write). Deployment target: the Bluestaq App Store at `comply-ops.apps.bluestaq.com`, detected template `python` (by `requirements.txt`).

> Deployment note, open: the flight plan specifies Azure App Service at `comply-ops.bluestaq.uk` and records the App Store as not applicable. This file follows the App Store instruction, which supersedes the flight plan's Azure Key Vault, staging-slot, Application Insights, and edge-restriction decisions. Adam Field owns the deployment decision and has not yet signed this off. `TBC, re-verify`.

## Hard rules (never violate)

● **No secrets in any shippable file**, in source or in history. Read secrets from the environment; render any value in docs as `[REDACTED:type]`. The pre-write hook blocks a credential before it lands.
● **No client-side access gate.** A hardcoded Personal Identification Number (PIN), flag, or hidden field in the browser is a User Experience gate, never security. Real gates are server-side.
● **Surgical edits only.** Change the smallest region that satisfies the request. Do not reformat, re-indent, or reconstruct regions you were not asked to touch.
● **Never invent a name, title, date, organisation, or figure** in user-facing content or data. If a fact is not verifiable, mark it with the explicit unknown marker (`TBC, re-verify`); do not assert it.
● **Every untrusted value is escaped or validated at the boundary**, and a control that cannot be verified is treated as failed (fail closed).
● **The container is the whole build.** A single `Dockerfile` installs from the hash-locked lockfile and runs the server; no separate bundler output. It runs as the non-root numeric user `10001:10001`, ships no package manager, carries no setuid or setgid bits, and is flattened to one layer.
● **Listen on `PORT`, default 8080, bound to `0.0.0.0`.** Never add `ENV PORT=` or `ENV DATA_DIR=` to the Dockerfile. Answer `/`, `/healthz`, `/health`, `/readyz`, `/livez`, and `/ping` with HTTP 200, unauthenticated, and never a redirect at the root.
● **A probe never raises and never hangs.** The storage probe converts every failure into a verdict and abandons a stalled write inside a bounded time. The diagnostics read-out is the recovery channel for a bad configuration value, so nothing in the probe path may prevent boot or block a request indefinitely.
● **Liveness never depends on a downstream.** A liveness path that probes Microsoft Graph or SharePoint restarts a healthy container during a transient outage of either. Dependency reporting belongs on `/readyz`.
● **Every register mutation writes one chained audit entry** through `complyops.audit` per AUD-001. No code path writes to SharePoint without it, and no code path calls Graph outside the client wrapper.
● **The audit chain is keyed, anchored, append-only, and never truncated.** Entries are signed with HMAC-SHA256 under a server-held key, so edit rights on the list are not enough to re-stamp a row, and the trusted anchor on the persistent volume is what detects a truncation or a wholesale rewrite. Verifying the whole log without the anchor is not a verification. Changing `FIELD_ORDER`, the digest construction, the chaining, or the field caps breaks every historical entry and is an irreversible decision requiring the Managing Director's sign-off. A golden test vector pins all of it.
● **Audit fields are validated, capped, and rejected at the boundary, never coerced.** An entry is immutable, so an over-collected or malformed field cannot be corrected or erased later without breaking the chain. That also means a cap cannot be added after the first entry is written.
● **No personal data content in any log, audit entry, health response, or client error.** An audit entry records that an action happened, never what the record said. Client errors are generic; the detail stays server-side.

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
wsgi.py                 the container entrypoint, reads PORT
Dockerfile              the whole build
tests/                  the suite, run against the uploaded package by the platform
scripts/verify.sh       the verification loop, one command
docs/                   deployment parameters and runbooks
.claude/                this baseline (skills, agents, output style, hooks, settings)
```

## Toolchain

Python 3.12, pinned in `.python-version`. Dependencies are exact-pinned and hash-locked in `requirements.txt` and `requirements-dev.txt`, compiled from the `.in` files with `pip-compile --generate-hashes`. Lint and format with `ruff` on the platform's analyser profile, not a looser default. Types with `mypy` in strict mode across the whole package. Tests with `pytest`, coverage to Cobertura XML at `coverage.xml`, which is the exact artefact the App Store Code Quality gate reads. Dependency scanning with `pip-audit`, where an unreachable advisory service is an honest skip locally and a hard failure in Continuous Integration.

## Quality bar

● Coverage at least 80% overall. This is the App Store gate's bar, and it supersedes the flight plan's 60%.
● Zero open analyser violations, because the quality gate fails on any one of them.
● A control is unfinished until a mutation shows it can fail. Measure a figure before asserting it.
● A leg that cannot run locally exits non-zero and says so. It is never reported as a pass.

## Naming and versioning

● Releases are `V2.0`, `V2.1`, and so on, held in `pyproject.toml` and surfaced by `/api/diagnostics`.
● The App Store slug is `comply-ops`: lowercase, hyphenated, a single hyphen only. A double hyphen breaks platform naming and fails the pipeline with zero stages run.
● Commit messages follow `[MODULE] short imperative summary` per AMD-001 section 10.3.

## House voice (applies to all prose, UI copy, comments, commits)

UK English throughout, in code comments, interface copy, documents, and commit messages. Ash's stated preference, recorded here so it is not re-litigated. Never fabricate data. Avoid the long em-dash; a single dash is fine. No `+` meaning "and" in prose. Use `●` for bullets, never a dash. Expand an uncommon acronym on first use. Lead with the decision, then the reasoning. Full voice: `.claude/output-styles/house-voice.md`.
