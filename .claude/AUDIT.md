# AUDIT.md

The map over this baseline: which source each part came from, the parameters you set per project and how to obtain each, and the security findings carried forward. Read this once before filling in `CLAUDE.md`.

## 1. What this baseline is

Bluestaq Foundations is one archetype-aware engineering baseline merged from two real Bluestaq systems: a single-file offline static web artifact (the "static" archetype) and a server-backed LLM container app (the "server" archetype). Every skill states which archetype(s) it applies to, so one bundle serves both without losing either's rigour. The App Store doctrine (`app-store-deployment`) is the shared deployment backbone.

## 2. Domain map (skill to source)

| Skill | Static source | Server source |
|---|---|---|
| getting-started | cold-start runbook | zero-to-deploy runbook |
| environment-setup | Node pin, browser driver | Node pin, Docker |
| glossary | static term set | server term set (union) |
| code-architecture | single-file, no build | createApp factory, container-is-build |
| dependencies | zero runtime deps | recorded-reason policy |
| data-layer | data-as-literals, build-pass | atomic JSON store, anti-shrink merge |
| api-and-integration | no-egress CSP | HTTP API, health, two-tier limits |
| llm-integration | (local tooling only) | pause_turn loop, prompt cache, cost cap |
| frontend-and-rendering | inline UI, vector renderer | served-static SPA, offline-first |
| state-management | view-state, rAF, storage wrapper | hydrated state, monotonic-rev sync |
| design-system | tokens, dual palette | tokens, components | (both aligned to Bluestaq brand) |
| testing-standards | validate, render-check, static-checks | node:test, in-process HTTP, Playwright |
| ci-cd | mirror-the-loop workflow | mirror-the-loop workflow |
| packaging | entrypoint-only zip, dated copies | lean .dockerignore context |
| observability-and-audit | no telemetry, human audit row | health/readiness, JSON audit line |
| security-hardening | CSP/escaper/no-egress, no client-side gate, env-only config | key+budget threat model and controls, auth (timingSafeEqual, route gating, CORS fail-closed, SSO seam), env-only config and two-stage App Store vars |
| release-and-deploy | object-storage path | container-is-the-build path |
| app-store-deployment | (shared) | App Store v2.0 doctrine |

## 3. Parameter table (set per project; how to obtain each)

Fill these in `CLAUDE.md`. Record any secret value as `[REDACTED:type]`, never the real value.

| Parameter | Meaning | How to obtain |
|---|---|---|
| `${PROJECT_ONE_LINE}` | one-line description | from the project owner |
| `${ARCHETYPE}` | `static` or `server` | decided in `getting-started` Step 0 |
| `${APP_SLUG}` | App Store slug (lowercase, hyphens) | chosen; must be unique in the store |
| `${APP_STORE_TEMPLATE}` | node-react / java-spring / python / docker-only / static-html | auto-detected from package contents (`app-store-deployment`) |
| `${NODE_VERSION}` | pinned Node major | the project's runtime (here 22) |
| `${BROWSER_DRIVER_PATH}` | absolute path to the browser driver | only if auto-resolution fails (`environment-setup`) |
| `${SOURCE_PATH}` | the artifact or source entry | the project layout |
| `${ENTRYPOINT_NAME}` | served filename (static) | commonly `index.html` |
| `${PRODUCT}` | product name for dated copies | from the owner |
| `${MAJOR}` / `${MINOR}` | version numbers | the release |
| `${INSTALL_CMD}` / `${TEST_CMD}` / `${DEV_CMD}` / `${BUILD_CMD}` | canonical commands | from `package.json` scripts |
| `${S3_BUCKET}` | static upload bucket | `bluestaq-appstore-uploads` (not the stale `bluestaq-appstore-bucket`) |
| `${S3_PREFIX}` | static object prefix | per project from the platform team |
| `${LLM_API_KEY}` | LLM provider key (server) | the provider; stored as an App Store secret, `[REDACTED:key]` in docs |
| `${ALLOWED_ORIGIN}` | production CORS origin (server) | the app's real origin, e.g. `https://${APP_SLUG}.apps.bluestaq.com` |
| `${STORAGE_MOUNT_PATH}` | persistent volume path (server) | `/data` when the file-storage add-on is selected |

## 4. Security findings carried forward

- **Client-side gate is not a boundary.** A browser PIN, flag, or hidden field is a user-experience gate only; the server token and server validation are the only security boundaries (`security-hardening`). Recorded as a standing anti-pattern.
- **`ENV PORT=` anti-pattern.** Setting a non-8080 port in the Dockerfile breaks the platform contract; the secret-scan hook flags it (`app-store-deployment`).
- **Stale bucket name.** `bluestaq-appstore-bucket` is stale; use `bluestaq-appstore-uploads` for static-html uploads (`app-store-deployment`).
- **Accepted risks (server).** The shared-token model (no per-user identity) and dataset confidentiality are deliberately out of scope; record them in the project security policy rather than leaving them implicit (`security-hardening`).

## 5. Completeness (coverage, standards, definition of done)

Proof the baseline has no gaps: every source area maps to an artifact, both archetypes are covered, every standard has an owner and a gate, and the definition of done is met.

### 5.1 Coverage (source area to artifact)

| Source area | Documented by |
|---|---|
| Cold start / onboarding | `getting-started`, `environment-setup`, `START-HERE.md` |
| Planning and kickoff | `flight-plan` (includes the kickoff interview) |
| Vocabulary | `glossary` |
| App structure | `code-architecture` |
| Dependencies and supply chain | `dependencies` |
| Config and secrets | `security-hardening` |
| Persistence | `data-layer` |
| Routes, health, rate limits, egress | `api-and-integration` |
| LLM calls (server) | `llm-integration` |
| Auth, token, CORS | `security-hardening` |
| UI structure and rendering | `frontend-and-rendering` |
| State and sync | `state-management` |
| Visual system and brand | `design-system` |
| Accessibility | `accessibility` |
| Tests and coverage | `testing-standards` |
| PR pipeline | `ci-cd` |
| Producing the package | `packaging` |
| Health, logging, audit | `observability-and-audit` |
| Defence posture | `security-hardening` |
| Deploy procedure | `release-and-deploy` |
| App Store target, tooling, per-stack recipes, readiness, gate compliance | `app-store-deployment`, `deploy-recipes`, `app-store-readiness`, `appstore-gate-compliance` |
| Binding and advisory review | `agents/engineering-reviewer.md`, `agents/security-reviewer.md`, `agents/deploy-gate.md`, `agents/design-critic.md` |
| House voice | `output-styles/house-voice.md` |
| Guardrails | `hooks/secret-scan.mjs`, `hooks/format-gate.sh`, `hooks/hooks.json` |
| Project memory / provenance | `CLAUDE.md`, `AUDIT.md` |

Unmapped: none.

### 5.2 Both-archetype coverage

Every domain skill names the archetype(s) it applies to. The static archetype is fully covered (single-file architecture, no-egress posture, inline renderer, CSP/escaper hardening, entrypoint-only packaging, object-storage deploy, human audit row). The server archetype is fully covered (createApp factory, HTTP API with health and rate limits, LLM integration, token auth and CORS, monotonic-rev sync, container-is-the-build, quality-gate testing, structured audit line). Shared concerns (config and secrets, dependencies, design system, CI, App Store doctrine, the gates, the house voice) apply to both.

### 5.3 Standards index (owner and gate)

| Standard | Owner | Gate |
|---|---|---|
| Archetype-correct architecture, no build (static) / container-is-build (server) | code-architecture, dependencies | engineering-reviewer |
| Exact-pinned deps, lockfile, npm ci, CVE scan clean | dependencies | engineering-reviewer and security-reviewer |
| No secret in repo/image/log; env-only config | security-hardening | secret-scan hook and security-reviewer |
| Atomic writes, anti-shrink merge, boundary validation | data-layer | security-reviewer |
| No egress (static) / health 200, two-tier limits (server) | api-and-integration | deploy-gate / security-reviewer |
| LLM key server-side, bounded loop, fail-closed parse, cost cap | llm-integration | security-reviewer |
| Constant-time token, route gating, CORS fail-closed, no client gate | security-hardening | security-reviewer |
| Escape all reflected input; instant-close panels; offline-first | frontend-and-rendering | engineering-reviewer and design-critic |
| One state object; rAF coalescing / monotonic-rev sync; prototype-strip | state-management | engineering-reviewer and security-reviewer |
| Token-only colours, Bluestaq palette, WCAG AA | design-system, accessibility | design-critic (advisory) |
| Verification loop / coverage 80%, parity, security-property tests | testing-standards | engineering-reviewer |
| CI mirrors local loop, least privilege | ci-cd | CI itself |
| Entrypoint-only / lean context, SHA-256, version normalised | packaging | deploy-gate |
| No telemetry and audit row (static) / health and JSON audit (server) | observability-and-audit | engineering-reviewer / deploy-gate |
| Full defence posture, each control a build-failing check | security-hardening | security-reviewer |
| Gated, human-confirmed deploy; non-root; port 8080; tested rollback | release-and-deploy | deploy-gate and human confirmation |
| Template, port, quality gate, image scan, deploy stage, never-do list | app-store-deployment, appstore-gate-compliance | deploy-gate |
| House voice (Smart Brevity, UK English, no invented facts) | output-styles/house-voice.md | design-critic (advisory) |

Every standard has an owner; every standard except the two advisory ones is verified by a fail-closed gate.

### 5.4 Definition of done

| # | Item | State |
|---|---|---|
| 1 | Both source bundles inventoried and merged without losing context | TRUE |
| 2 | Every source area maps to an artifact (coverage table) | TRUE |
| 3 | All twenty-nine skills present with the full completeness-limb structure | TRUE |
| 4 | Skills named in plain English and as Claude-compatible skill names | TRUE |
| 5 | Modern frontmatter, org-upload-schema-clean (name and description only; no Claude Code extension keys) | TRUE |
| 6 | Both archetypes fully covered; rigour preserved from each | TRUE |
| 7 | Flat file layout rehydrating to .claude/ via REHYDRATE.md | TRUE |
| 8 | App Store doctrine embedded as the deployment backbone | TRUE |
| 9 | House rules honoured (UK English, no em-dash, no dividers, no "+") | TRUE |
| 10 | plugin.json lists all twenty-nine skills, four agents, output style, hooks | TRUE |

No item is false.

## 6. Provenance

Merged verbatim-faithfully from two extracted foundations bundles and the authoritative App Store reference (`appstore.md`, v2.0). No project-specific business data is embedded; every product-specific value is a `${PARAMETER}` set per project. Where a server-side detail was referenced but not uploaded (api-layer, auth), it was reconstructed from the security-hardening and getting-started references and marked as such in the owning skill's provenance.
