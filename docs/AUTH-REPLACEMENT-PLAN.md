# Replacing Entra ID as the identity provider: scope and plan

Bluestaq Ltd, Directive (`directive`). Drafted 2026-11-06 for the decision of the UK
Information Security Officer. **Nothing in this plan is approved and no code has changed.**
It exists to be argued with before anything is built.

## The blocker

IT have confirmed that this application cannot authenticate users against the Bluestaq Ltd
Entra ID tenant. That removes the identity provider the application was built against, the
one named in the signed accreditation, and the one AMD-001 section 10.4 requires by name.

**Record the reason before anything else.** This plan does not state WHY the tenant is
unavailable, because that was not supplied and inventing it would put a fabricated
justification into the record that an assessor reads. `TBC, re-verify` with IT and write
the real reason into the AMD-001 amendment. The distinction matters to the choice below: a
tenant that cannot host a new application registration is a different problem from a tenant
that cannot be reached from the App Store's network, and they do not have the same answer.

## What this does and does not break

Measured against the code rather than assumed.

**It does not break the authentication architecture.** `src/directive/auth.py` is 524 lines
and exactly 16 of them are Microsoft-specific. Proof Key for Code Exchange, the `state`
parameter, the `nonce`, the issuer, audience and expiry checks, and the back-channel token
exchange are all plain OpenID Connect. `actor_from_claims` already falls back through
`preferred_username`, `upn`, `email` and `sub`, which are standard claims.

The Microsoft-specific parts are:

| What | Where | Why it is specific |
| --- | --- | --- |
| `ENTRA_HOST` | `auth.py:295` | One hardcoded hostname |
| `authorise_endpoint`, `token_endpoint`, `expected_issuer` | `auth.py:329-342` | Three functions composing Microsoft-shaped URLs from `TENANT_ID` |
| `MFA_METHOD = "mfa"` | `auth.py:322` | An `amr` value, which is RFC 8176 and not Microsoft's invention |

**What it does break is the paperwork, and that is the larger half of this job.**

| Record | What becomes false | Owner |
| --- | --- | --- |
| AMD-001 section 10.4, confirmation 1 | The policy REQUIRES "Authentication via Entra ID with MFA". The policy itself has to be amended; this is not something the build can satisfy differently. | Adam Field |
| `docs/ACCREDITATION-REVIEW.md`, the signed V2.2 decision | Row 1 reads "Met, and accepted" against Entra. It becomes untrue on the day the provider changes. | Ash Higgins, as UK ISO |
| AMD-001 section 11.5, penetration test scope | Already carries a referred correction from "Graph API token handling" to "Entra ID token handling". It now needs the real provider's name. | Adam Field |
| `docs/ACCREDITATION-REVIEW.md`, confirmation 2 | Least privilege is accepted on the basis that "the access list IS the Entra assignment list". Whatever replaces Entra has to supply an access list, and somebody has to own it. | Ash Higgins |
| IASME Cyber Assurance, access control | The certification was granted against a described access-control arrangement. A change of identity provider is a change to it. | Ash Higgins |

## The options

Three, and they are not equally good. The second column is the one that decides it.

| Option | Where the audit actor comes from | Who owns the user list | MFA | Code |
| --- | --- | --- | --- | --- |
| **A. OIDC against the platform's Keycloak** | A token this application verified itself | The platform's Keycloak realm | Keycloak's, if configured | ~16 lines generalised, plus configuration |
| **B. The platform's SSO gateway in front of the app** | An HTTP header the gateway sets | The platform's Keycloak realm | Keycloak's, if configured | Delete the sign-in flow; trust a header |
| **C. Local accounts inside the application** | A password this application checked | Us, by hand, for ever | Only if we build it | A new subsystem: storage, hashing, rotation, lockout, TOTP, reset, deprovisioning |

### Option A, recommended

The App Store already runs Keycloak: the platform's own tooling authenticates against it by
device-code flow, and the platform can place a Keycloak gateway in front of an application.
So an identity provider exists, it is the platform's rather than the Bluestaq Ltd tenant,
and it is therefore not the thing IT has blocked, **subject to the first decision below.**

This keeps the property that put authentication inside the application in the first place:
the audit entry's actor comes from a token this application verified, not from a header a
caller reaching the pod directly could assert. That sentence is in `CLAUDE.md`, it is the
stated basis for satisfying AMD-001 10.4, and it is the thing worth not losing.

The work is to make three functions read their endpoints from configuration rather than
compose Microsoft URLs. Everything else in the flow is already standards-based.

### Option B, not recommended, and the reason is specific

A gateway authenticates the BROWSER and then tells the application who the user is, in a
header. The application cannot distinguish that header from the same header set by anything
else that can reach the pod. `docs/DEPLOYMENT.md` already records the deployment shape where
the pod is reachable directly, and the whole audit attribution argument rests on the actor
being unforgeable.

It becomes defensible only with a network policy that makes the gateway the sole route to
the pod, plus a shared secret between gateway and application, plus evidence of both for an
assessor. That is more platform work than Option A is application work, and it ends in a
weaker position.

Worth stating plainly: the SSO gateway is probably coming anyway, as a platform default. The
question is whether the application TRUSTS it for identity, and the answer should be no.
Exempting the six health paths from it, as `docs/DEPLOYMENT.md` already says to request,
remains correct under Option A.

### Option C, the fallback, with its real costs

Local accounts are the obvious reading of "user logins", and they are the most expensive
option by a wide margin. Not because the login form is hard, but because an identity
provider is not a login form. It is:

● Password storage, hashed with a memory-hard function (Argon2id), which is a new runtime
  dependency in an application that currently ships nine and audits them hard.
● Multi-factor authentication. Without it this is a DOWNGRADE from the signed accreditation,
  not a sideways move. Time-based one-time passwords mean a secret per user, an enrolment
  flow, recovery codes, and a story for a lost device.
● Credential lifecycle: a reset flow that is not itself an account-takeover path, a lockout
  policy that is not a denial-of-service path, and rotation.
● **Deprovisioning, which is the one an ISM should ask about first.** With Entra, a leaver
  loses access when IT disable the account. With local accounts, somebody at Bluestaq Ltd
  has to remember Directive exists on a person's last day, for ever. That is a named control
  in every certification this company holds, and the honest version of this plan says it is
  a new manual process rather than pretending the application absorbs it.

If Option A is impossible, Option C is the answer and the plan below scopes it. It should
not be chosen while Option A is available.

## The decisions, before any code

These are not for me. Work does not start until the first two are answered, because they
change which plan this is.

1. **Can Directive be registered as a client of the platform's Keycloak realm?** For IT and
   the App Store platform team. Needed: a client ID, a client secret, the realm's issuer URL
   and its authorisation and token endpoints, a registered redirect URI of
   `https://directive.apps.bluestaq.com/auth/callback`, and an answer on whether the realm
   enforces multi-factor authentication and asserts it in `amr`.
2. **If the Keycloak realm federates to the same Entra tenant, does the blocker follow it?**
   This is the question that decides whether Option A is real. A Keycloak that is a front end
   to the blocked tenant is the blocked tenant. Ask explicitly; do not infer from the fact
   that the App Store itself works.
3. **Who owns the access list, and the leaver process against it?** Under Option A, who adds
   and removes people in the Keycloak realm. Under Option C, who disables a local account on
   someone's last day. Name the role, not a person, and write it into the accreditation.
4. **Is a release without multi-factor authentication acceptable as an interim?** My
   recommendation is no, and that it is better to hold the deployment than to deploy a
   compliance system of record behind a single factor. If the answer is yes it must be a
   written, time-bounded acceptance in the accreditation, not a silence.
5. **Does AMD-001 get amended before or after this ships?** The policy names Entra ID. The
   build cannot comply with it under any option here. Adam Field owns the amendment, and
   until it lands every release is formally non-compliant with 10.4 whatever it does.

## Scope of work, Option A

Sized against the code. The estimates are of change, not of calendar.

**Application, small.**

● Replace `ENTRA_HOST` and the three URL-composing functions with configuration:
  `OIDC_ISSUER`, `OIDC_AUTHORISE_URL`, `OIDC_TOKEN_URL`. Explicit endpoints rather than
  discovery, because a discovery fetch at boot is a downstream dependency on the start-up
  path and `CLAUDE.md` forbids liveness depending on a downstream.
● Keep `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`. Retire `TENANT_ID`.
● Keep every check: PKCE, state, nonce, issuer, audience, expiry, `amr`.
● `actor_from_claims` needs no change; Keycloak issues `preferred_username`.
● `describe()` and `/api/diagnostics` stop naming a tenant and name an issuer.

**Tests, moderate.** `tests/test_entra_sign_in.py` is 419 lines and drives the whole flow
against a fake token endpoint. It is provider-agnostic in substance and needs renaming and
re-pointing, not rewriting. Add: a refusal when the issuer does not match, and a refusal
when `amr` lacks the MFA method, both already present in shape.

**Records, the largest part.** The accreditation re-review, the AMD-001 amendment request,
`docs/DEPLOYMENT.md`'s environment table and known gaps, `CLAUDE.md`'s statement of why
authentication is in the application, and `docs/OWASP-TOP-10-TEST.md` A07.

**Gates.** This is a security-relevant change to the authentication boundary. It goes
through `security-reviewer` and `engineering-reviewer`, and the deploy gate afterwards.

## Scope of work, Option C

Only if Option A is ruled out. Sized honestly: this is the largest single change in the
application's history, larger than the two transfer registers.

● A credential store on the persistent volume, with the same atomic-write and anchor
  discipline the registers already have, because an account file that can be truncated is an
  authentication bypass.
● Argon2id hashing. One new runtime dependency, hash-locked, and the first in this build
  whose compromise is directly an authentication bypass.
● TOTP enrolment, verification, recovery codes, and a rate limit on verification that does
  not become a lockout denial-of-service.
● An administrative path to create, disable and reset an account, which is a privileged role
  in an application that currently has exactly one role. That is a second role, and the
  accreditation's "one role" acceptance stops being true.
● Audit events for every one of those: account created, disabled, password changed, TOTP
  enrolled, TOTP reset, lockout. AUD-001 covers authentication events; these are new
  categories and the field set has to carry them.
● A documented leaver process, owned by a named role.

**Note on the audit log under Option C.** The attribution argument changes shape but
survives: the actor comes from a password this application checked rather than a token it
verified, which is still not a header a caller can assert. The weakness moves from the
boundary to the credential, which is why the MFA question above is not optional under this
option.

## Risks

● **The Keycloak realm turns out to federate to the blocked tenant.** Decision 2 exists to
  find this out before work starts rather than after.
● **Keycloak does not enforce MFA.** Then Option A arrives at the same place as Option C on
  the one axis that matters most, and decision 4 has to be answered honestly rather than
  waved through because the code was easy.
● **The accreditation is re-signed in a hurry.** The V2.2 record took real work and says
  precise things. Changing the provider in row 1 and leaving the rest is how a record starts
  over-claiming, which has happened in this project before and was caught by a gate each
  time. The re-review is a re-review, not an edit.
● **The interim.** The application does not boot without an identity provider, by design.
  Between now and whichever option lands, there is no deployed Directive. That is the correct
  behaviour and it is also a real cost, and it should be stated to whoever is waiting for the
  Transfer Risk Assessment capability.

## Sequence

1. Answer decisions 1 and 2. Nothing starts before this.
2. Ash records the chosen option and the reason, and raises the AMD-001 amendment with Adam
   Field. The amendment does not have to LAND first; it has to be raised, so the gap is
   recorded rather than discovered.
3. Build the chosen option behind the existing gates.
4. Re-review the accreditation properly, as a re-review, with the conditions re-examined
   rather than carried.
5. Deploy, with the `securityContext.fsGroup` and health-path exemption requests unchanged.

## What I am not doing yet

No code. The authentication boundary is the one part of this application where building
first and deciding afterwards is the wrong order, and decisions 1 and 2 can change the
answer completely.
