# Changelog

Directive (`directive`). One row per release, recording the
version, the commit it shipped from, the binding gate verdicts, and the deviations open at
that point. AMD-001 section 10.3 governs the commit messages behind each row; this file is
the release-level record the deploy gate reads.

Dates are UTC. A release is not "shipped" until it is deployed, and nothing has been
deployed yet, so every row below records a release that was cut, gated and merged.

## V2.6, 2026-11-10, the same work under a number no other package carries

**Why this release exists, and it is not new work.** Everything in it is the V2.5 section
below. The number moved because `dist/` already holds `directive-2.5-20261109-0445d61.zip`,
built on 2026-11-09 from `0445d61`, which is the commit the FIRST security gate run of this
release scored. Twenty gate rounds have landed since: the derived enrolment secret, the
bounded lock, the hash upgrade, the audit-reach fix in `accounts.load`, and the shed-versus
-fault separation. A package built today is not that package by any measure an operator
could check, and the platform shows an operator only the version.

**The rule this follows is V2.4's, and it was bought at the price of a whole release.** V2.3
went to the App Store four times under one version from four different commits, so
`build-package.sh` now refuses to package a version it has already packaged from a different
commit. It offered two ways out: bump, or delete the stale archive and rebuild 2.5. **Taken
the first, on a fail-closed reading.** Whether that archive was uploaded is not recorded
anywhere this repository can read. The header above says nothing has been DEPLOYED, which is
true and not the same question, since V2.3's four uploads were all rejected without ever
being deployed. A control that cannot be verified is treated as failed, so the assumption is
that a 2.5 may exist on the platform, and the cost of being wrong is one unused version
number against the exact failure V2.4 exists to prevent.

**Gate position at this version.** `security-reviewer` PASS at `c10a197`, carried forward:
every change since is held by the fifth engineering round's mutations and the loop, and the
round itself judged the slice not to need re-referral. `engineering-reviewer` FAIL at
`533e57f` with its two control findings fixed in `0f012d7` and everything else recorded as
accepted residual in `docs/GATE-RECORDS.md`. **This release is therefore cut with one binding
gate outstanding, which is Ash's decision and is stated here rather than implied.** The
deploy gate reads this file and will see it.

## V2.5, 2026-11-08, Entra ID out, a local account list in

**Why this release exists.** The IT team confirmed that this application cannot
authenticate users against the Bluestaq Ltd Entra ID tenant. That removed the identity
provider the application was built against, the one the signed accreditation names, and the
one AMD-001 section 10.4 requires by name. `docs/AUTH-REPLACEMENT-PLAN.md` set out three
options; Ash chose Option C, local accounts, on 2026-11-08. The reason the tenant is
unavailable was not supplied and is recorded as `TBC, re-verify` rather than invented.

**What a sign-in is now.** A username and a password, verified against a stored scrypt hash
at the Open Web Application Security Project's minimum parameters (N=2^17, r=8, p=1, so 128
MiB and about 430 milliseconds per attempt on the build host), and then a time-based
one-time password per RFC 6238 which every account enrols at first sign-in, with ten
single-use recovery codes. A correct password alone grants nothing: the half-finished state
is a PENDING marker that `current_actor` does not read, so no route behind the gate can see
it, and it expires after 300 seconds. scrypt rather than Argon2id because it is in the
standard library, and this build installs with `--only-binary :all:` from hash-locked
lockfiles: a new runtime dependency for a hash the standard library already ships at the
recommended parameters is a worse trade than it looks.

**What went with Entra ID.** `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URI`;
the `/auth/callback` route; the authorisation code flow with PKCE; the `amr` check added in
V2.2; and the recorded deviation that the identity token's signature was never verified,
which is closed by removal rather than by work. There is now no outbound HTTP call anywhere
in the application: no HTTP client is imported under `src/`.

**What arrived with the account list.** `BOOTSTRAP_ADMIN` and `BOOTSTRAP_ADMIN_PASSWORD`
create the first administrator when the list is empty, and that account must change its
password at first sign-in, so the value that travelled through the platform's environment is
replaced by one only that person knows. A second role, `admin`, governs account
administration only and does not partition the registers. Every account-administration
route writes an audit entry, refusals included, and the last enabled administrator cannot be
disabled or demoted.

**What the account file is held to.** It is a credential store on the persistent volume, so
it is written at mode 0600 before any byte reaches it, then fsynced and renamed. It lives
under `DATA_DIR/accounts/` and deliberately NOT under `DATA_DIR/records/`, which the export
globs: a password hash must not be able to leave the volume inside an exported register, and
a test asserts the directory as well as the absence. `redacted()` is an allowlist of nine
fields rather than a denylist, because a denylist is one new field away from leaking it.

**Boot deliberately does not read the account list.** The Entra check in `check_startup` is
gone and is NOT replaced by a check that an administrator exists. An empty or unreadable
list is recoverable at runtime and a storage fault that refuses the boot is a crash loop
that takes the diagnostics read-out, the recovery channel, down with it. A test holds that,
including against an account file that cannot be parsed.

**Figures that moved with the tree, re-measured rather than edited.** Both of the credential
sweep's widening experiments cost more on this tree than on the last one, because the tree
gained modules. The numbers are not restated here: they live beside the rules in
`scripts/build-package.sh` and under Open in scope in `docs/GATE-RECORDS.md`, each re-run
against the live rules by `tests/test_sweep_cost_figures.py` on every build. Restating a
measured figure in a fourth place is how this project shipped a wrong one three times.

**Three instruments caught something real and are recorded because they did.**

● The cross-site request forgery walk read a 302 from `@auth.admin_required` as proof of a
  token check on the five new account-administration routes. The authorisation refusal fires
  first, so deleting `@csrf.required` from any of them would not have disturbed it. The walk
  now raises the session to administrator so the token is the only thing left that can
  refuse, and a mutation confirms it reds.
● The audit-entry construction rule failed closed on `rows.append(created)` in
  `account_routes.py`, where `rows` is the account list rather than the audit chain. Fixed
  by removing the append, not by widening the exemption list the rule reads.
● The sweep over the staged package reported the new suite's test password. It was a true
  positive on a line shaped like a credential in a file the package ships, and the comment
  beside that line said it matched no credential pattern, which was an over-claim. The line
  is now declared in the exemption ledger by path, match count and digest, and the second
  test password was collapsed into one derived from it so the exempt surface stayed at one
  line rather than growing to two.

**What the binding security gate found, and what it changed.** The gate failed this
release at `0445d61` with four MAJORs. Three of them were in the running application rather
than in machinery or records, which has not happened since `896ee9f`, and the first was a
working bypass.

● **A one-time password was not one-time.** Nothing recorded the counter a code was
  accepted at, so one six-digit code signed in three consecutive fresh clients and the
  enrolment code was replayed from a second session into a complete sign-in. RFC 6238
  section 5.2 carries exactly one normative MUST NOT and it is this. `totp.py` claimed to be
  "held against the specification rather than against its own output" while omitting it: the
  Appendix B vectors cover the arithmetic and never covered the protocol. The counter now
  lives on the account as `totp_last_step`, a code must match a counter strictly greater
  than it, enrolment spends its own confirming code, and an unreadable counter refuses every
  code rather than accepting every code. Four mutations killed, including the subtler `==`
  form that would still have allowed a code from earlier in the window.
● **A busy hash slot was counted as a wrong password.** `verify_password` swallowed the
  load-shedding case, so ten of them locked the account and wrote an AUD-001
  `ACCOUNT_LOCKED` entry blaming credentials that were correct. `ServiceBusyError` now has
  its own class and the two routes that write audit entries catch it first and record
  nothing. The binding ground is the evidence rule, not the availability one: an immutable
  log that says somebody got their password wrong when they did not is a record that
  over-claims in front of an assessor.
● **The sole administrator could be locked out with no way back.** Ten guesses every
  fifteen minutes holds any account locked, the unlock route is behind the administrator
  role, and the recovery `docs/DEPLOYMENT.md` documented restored nothing. `BOOTSTRAP_UNLOCK`
  is the narrow replacement: set it, restart, sign in, remove it. It clears the lockout and
  nothing else, and it writes an audit entry with a source address of `boot`, which is the
  whole reason to prefer it over hand-editing the volume. The denial of service itself is
  not closed and is recorded as accepted residual, because a per-address limiter belongs at
  an edge this platform does not provide.
● **The timing half of the enumeration defence was held by nothing.** Replacing
  `absorb_timing`'s body with `return` left all 1547 tests green: the test named for it
  called it and asserted nothing. It now counts hashing calls, which is deterministic where
  a timing band would flake.

Three MINORs with it: `Cache-Control: no-store` on the two pages that render a plaintext
secret, a corrupt account file answering 500 with no audit entry on the unauthenticated
sign-in route, and stale Entra prose in `__init__.py`.

**The re-run then failed the build again, on the fix itself.** It confirmed all four MAJORs
dead by live attack, including a six-way concurrent race on one code, and found that the
single-use control was held by no test: restoring the counter on the success branch of
`/sign-in/verify` left all 1565 tests green while one code signed in three fresh clients
again. The coverage report named that branch as never executed. Every helper in the suite
completes a first sign-in through enrolment, so no test had ever posted a valid, unspent
code to the verify route, and the test named for that property was a duplicate of the
enrolment one beside it. Two docstrings claimed the coverage existed; one named a module
that never calls the function.

That is the sixth time this project has shipped a correct control that nothing held, and
the first time the control was written the same day as the claim about it. Two tests now
post a fresh code to the verify route and replay it, split so that one fails if the route
refuses a good code and the other fails if it accepts a spent one, with the one-time
password clock moved forward after enrolment rather than the stored counter edited. The
gate's own mutation now reds. The duplicate test is deleted rather than left to look like
coverage, and both docstrings now name the tests that actually hold the property.

Six MINORs with it, each mutation-proved: the real `ServiceBusyError` raise sites were
executed by nothing because every test patched `_scrypt` to raise, so an unconverted
`MemoryError` would have escaped as a 500; the explicit `except` was not independently
held, since the blueprint handler catches the subclass and answers identically while
calling a capacity event "the account list could not be read" in the log; the break-glass
audit entry is written after the unlock is persisted rather than before, so the docstring
and the runbook now say it is best-effort with the pod log as the backstop;
`BOOTSTRAP_UNLOCK` was missing from the suite's managed variables; the named-account test
passed by file order; and one stale Entra sentence survived in `security_headers.py`.

**And a third round, on the same axis again.** The gate confirmed everything dead by live
attack, including the previous mutation verbatim, then failed the build because the fix for
the previous round's sixth MINOR did not work. That MINOR was a test passing by file order;
the fix locked the member first in TIME, and the mutant reads file ORDER, where the
bootstrap administrator is row 0 whatever order the locks arrive in. The mutant survived
the whole suite and the comment written with the fix asserted it did not. The member is now
moved to row 0, which is what the mutant actually reads, and the comment says so.

Four MINORs with it, each mutation-proved: `BOOTSTRAP_UNLOCK` had to equal `true` and only
the absent case was held, so a mutant reading "any non-empty value" would have turned the
recovery ON for an operator who set it to `false`; the pod-log warning had just been
promoted into a documented compensating control in two shipped places while deleting it
left the suite green; the non-short-circuiting comparison loops in `totp.matching_step` and
`accounts.spend_recovery_code` were held by nothing although both docstrings state the
property in full, so a structural pin now refuses a `return` or `break` inside either loop;
and a new test acquired semaphore slots outside its own `try`.

**Two observations acted on rather than filed.** The suite does not shuffle:
`pytest-randomly` is installed nowhere and is in no lockfile, so `-p no:randomly` is
silently unrecognised and the file-order dependence above could never have surfaced by
itself. Recorded here because three rounds of this project's reporting, this file included,
have implied otherwise. And the post-sign-in `next` target was discarded on every two-factor
sign-in: `auth.sign_in` clears the session, correctly, and the target was read after that
call, so every sign-in landed on the dashboard whatever link the person followed while three
places in the module described a `next` that worked. It failed safe, which is why nothing
noticed. The target is now read before the session boundary, and the origin guard that makes
carrying it safe is held on that path by four hostile payloads rather than assumed from the
one-step path.

**The fourth round found the one that matters: revoking an account did not revoke its
session.** The decorators decided from the signed session cookie, which carries a copy of
the role taken at sign-in, so a revocation took effect at the next sign-in rather than the
next request. Within the eight-hour session window the gate drove a disabled account into
reading every register, writing a compliance record and pulling the whole evidence export;
a demoted administrator into undoing their own demotion; and a disabled administrator into
re-enabling themselves, disabling the administrator who had disabled them, and creating a
fresh administrator to persist with. Reproduced here before it was fixed.

Three shipped records said otherwise, which is the part that makes this worse than a bug.
`docs/ACCREDITATION-REVIEW.md` told an assessor that local accounts outlive employment
"unless somebody disables an account"; `docs/DEPLOYMENT.md` said the `admin` role governs
account administration only; and `views/account_routes.py` said the last administrator
cannot be removed. Each is now corrected to say what disabling and demoting actually do and
when they take effect.

`auth.live_role` is the fix: every authenticated request re-reads the stored account and
answers from it. Absent, disabled or locked grants nothing; the ROLE is read live rather
than compared against the session's copy, so a demoted administrator is simply a member
from the next request with their session intact; an unreadable account list grants nothing
at all; and development, which has no account list, is exempt. The cost is one small JSON
read per authenticated request, which is the price of a revocation that takes effect.
Fifteen tests hold it and three mutations kill it.

Four MINORs with it. The break-glass fixture agreed with two more wrong selection rules:
the administrator is both the last row of the account file and the lowest username, so
"last locked" and "alphabetically first" each still picked the right account. A third
locked account now disagrees on all three axes. The structural short-circuit pin was evaded
two ways, by a `continue` guard and by a `while` whose own test watches the flag, so it now
refuses `Continue` and `Raise` and a `while` testing a name its body assigns, with a
counting assertion beside it that holds the property rather than a spelling of it. The
stored `next` target was uncapped and is now 512 characters. And the previous commit
message said 1583 passed where the tree gives 1584; the coverage figure was right.

**The fifth round failed on a record contradicting its own code, and on two session
remedies that did not evict anybody.**

Three places in the tree said the session survives an account list that is merely
unreadable, while the refusal path cleared it on both branches. Corrupt the file, make one
request, restore it byte for byte, and the user was signed out for good, unable to sign back
in because the sign-in route reads the same file. Worse, the one line those three paragraphs
existed to justify was held by nothing: because every refusal cleared the cookie, the
redirect loop it prevents was not reachable, and reverting it left 289 tests green. The
record was right about what should happen; the code was not. Fixed by making the behaviour
match the record rather than the other way round: a revocation clears the session and a
fault does not, which makes that line load-bearing and its mutant lethal.

**Sessions now carry an epoch.** Disabling an account already ended its sessions. A password
change and a second-factor reset did not, and a gate measured a cookie captured beforehand
still working through both. That matters most for the change-your-own-password form, whose
own docstring names a session left open on an unlocked machine as the ordinary way an
account is taken over: requiring the current password evicts nobody, because whoever took
the session already has it. The account carries an integer that a password change and a
factor reset bump, the session carries a copy, and a mismatch is a revocation. Changing your
own password leaves your own session alone and ends every other one.

Two MINORs with them. The break-glass fixture agreed with a FOURTH wrong selection rule,
most-recently-locked, because the administrator was locked last; it is locked first now and
four rules disagree with the named lookup. And `enrol_page` was the only one of the three
second-factor routes not to check `may_sign_in`, so an account disabled between the first
factor and the second was still shown a fresh secret and still wrote a pending one to its
row in the credential store.

**The sixth round failed on the same class twice over: a control narrowed rather than
closed, and three epoch mutations nothing caught.**

`accounts.load` called `Path.exists` outside its own `try`. `pathlib` swallows only a
handful of errno values, so a restricted or differently-owned mount came through as a bare
`OSError`, missed both blueprint error handlers, and answered `POST /sign-in` with 500 and
no audit entry. The handler exists to prevent exactly that and its docstring said it did;
the class had been narrowed to the unparseable-JSON trigger. Every operating-system error
is an `AccountError` now, the existence check included, and the realistic trigger is named:
a container running as `10001:10001` against a mount it cannot read.

Three mutations on the epoch path survived the whole suite, two permissive. `epoch_of`
returning zero on a corrupt value is the behaviour its own docstring warns against by name.
`_session_epoch` returning zero instead of the fail-closed `-1` is the guard that refuses a
cookie minted before the field existed, against any account still at epoch zero, which every
account is until its first password change. And the line copying the live epoch onto a new
session was held by nothing, because no test signed a client in after that account's epoch
had moved. Three tests now, one per guard, each mutation-proved.

Seven MINORs, every one acted on rather than filed. A missing account file read as a
revocation and cleared every cookie, which is the sibling trigger of the fault case closed
the round before. `epoch_of`'s docstring claimed an unreadable epoch returns a value no
session can be carrying, while a fresh sign-in was handed exactly that value; a sign-in
whose stored epoch is unreadable is refused now. A password change did not invalidate an
outstanding half-finished sign-in, which a gate drove from the old password to a complete
session; the marker carries the epoch too. `/api/diagnostics` was the last authenticated
response still deciding from the session cookie, so a revoked account still read the
credential-presence map; it gates on standing now, and deliberately still answers a session
whose account list cannot be read, because that is the fault the read-out exists to
diagnose. A cookie idle across a disable and a later re-enable was honoured again. And
`sign_in`'s `epoch` parameter defaulted to zero, the permissive value, which is a trap with
a type annotation on it.

**Three Entra leftovers are deleted rather than left to look like controls.**
`constant_time_equal` compared the sign-in state and had no caller in `src/` after that
provider went, while a test pinned it as "a secret on an unauthenticated route" that no
route passed through: a pin naming a function nothing calls cannot fail. `describe` said it
fed the diagnostics read-out, which builds its own report and never called it.
`bootstrap_configured` was called only by `describe`. Deleted rather than wired in, because
adding account counts to a shipped response is a disclosure decision and not a tidy-up.

**The seventh round found an account takeover, and it is the most serious finding of this
release.** `enrol_page` reuses a stored pending second-factor secret rather than minting one
per load. It has to: minting on every GET meant refreshing the page invalidated the code the
person had just scanned, which this build fixed in V2.5's first commit. But the reuse read
the ACCOUNT, so two callers who both knew the password were shown the same secret. An
attacker loads the enrolment page before the real owner ever signs in; the owner is then
shown the attacker's secret, confirms it, and the attacker holds the account's live second
factor. Reproduced independently before fixing, and the precondition is weaker than it
first appears: no administrator action is involved, and for the bootstrap administrator the
attacker is anyone who can read the platform's environment tab, a reader
`docs/DEPLOYMENT.md` already names.

An unconfirmed secret now belongs to one half-finished sign-in. `begin_enrolment` returns a
random token with it, the session holds the token and the secret stays on the volume, and
only the holder can be shown it again or confirm it. A second session gets a fresh secret.
An epoch bump clears the pending secret as well, so "every session this account holds
stops" includes one that is holding a secret. The refresh behaviour the account-wide reuse
existed for is held by its own test, because a fix that minted afresh every time would
satisfy the takeover test and reintroduce the original defect.

**The round's other three MAJORs were the previous round's new gates held by nothing.** The
corrupt-epoch refusal at the second factor survived `if False:` across the whole suite. The
test named for it could not fail: it asserted that a redirect location contained
`/sign-in`, which is satisfied by `/sign-in/verify`, the success destination. And
`enrol_submit`'s half of the pending gate survived deletion.

**Both replacement tests then passed for the wrong reason on first writing**, and that is
recorded because it is the same failure one layer along: one was satisfied by the replay
counter rather than the epoch, the other by the secret-clearing rather than the gate. Each
was corrected until the mutant it names dies for the reason it names, which took isolating
the condition rather than merely reproducing the attack.

Four MINORs with them, all closed: `file_present`'s docstring named the wrong order of
operations, `KeyError` sat in a catch while the key it protects was read outside the `try`,
`epoch_of(None)` was dead fail-closed code that read as a held control and is now excluded
by the type, and `docs/AUTH-REPLACEMENT-PLAN.md` cites code deleted in V2.5 and now says so.

**The eighth round found the takeover's own fix held by nothing, and the reason is worth
reading twice.** Bypassing the token comparison, or replacing the random token with a
constant, left all 1614 tests green while the attack came back. The test written for the
takeover could not see it: the owner in that test arrives with no token at all, so the
comparison is never reached, and the empty-token guard above it is what refuses. The attack
needs a SECOND load by the attacker, after the owner has minted, which is the only path on
which the comparison decides anything. One test covering that path kills all three mutants
of the family.

**A claim written in the previous commit is wrong and is corrected here.** That commit said
`finish_enrolment`'s ownership check is a second layer that cannot be reached, reasoning
that the enrolment page replaces the secret whenever the token does not match. The request
token is per session rather than per form, so a POST needs no intervening GET, and the gate
measured the clause entered with both tokens present and refusing. It remains unexploitable,
because a stale token means the stored secret has already been replaced and no code path
changes one without the other, so it is now recorded as reachable and untested rather than
given a test that would pass on the code mismatch and prove nothing. The correction stands
in the code; the sentence was never in this file, which is one detail of the gate's report
that was itself wrong and is not accepted. The ninth round was given that correction and
accepted it.

Three more things were held by nothing and now are: the clearing of the pending secret at
confirmation, which is the only guard on a second pass through `finish_enrolment`;
`session.clear()` in `sign_in`, whose own docstring asserts that no pre-authentication value
crosses the boundary; and the token's LENGTH, which the route-level test cannot see because
a one-byte token is still unique. And `reset_factor`'s own call to `clear_pending_enrolment`
was redundant with the one inside `bump_epoch`, so it was fail-closed code that read as a
held control and held nothing: the same class as the `epoch_of(None)` branch removed a
commit earlier, and it is deleted the same way.

**Two residuals are recorded rather than fixed**, both measured, and both re-measured and
re-worded at the ninth round below, because each sentence described code that the ninth
round then changed: a second party who knows an account's password can stop its owner
completing a first enrolment; and `GET /sign-in/enrol` writes to the credential store
without a request token, which gains a cross-site caller nothing because they cannot read
the response. The rows in `docs/GATE-RECORDS.md` carry the current figures and are the
record; these two lines are kept short on purpose, because a figure repeated in two files
is a figure that goes stale in one of them.

**The ninth round found two MAJORs, and the first was a boundary disagreeing with a
boundary.** `normalise_username` accepted a username beginning `=`, `+`, `-` or `@`, which
the audit boundary's `FORMULA_LEAD` refuses, so an account could be created whose own
administration entries could never name it: the evidence would read `unrecordable` where the
subject should be, irreversibly, because an entry cannot be rewritten. The fix imports the
audit boundary's own set rather than mirroring it, and a test asserts the two names are one
object, because this build has already shipped a mirrored rule set that drifted.

**The second is the enrolment page as a write amplifier.** The token that owns an
unconfirmed secret was minted BY the page, so a cookie captured at the first factor carried
no token and every replay of it was served a freshly minted secret: twelve replays, twelve
secrets, twelve writes to the credential store, from one password verification. The token is
now minted in `begin_second_factor`, at the first factor, where a replayed cookie already
carries it; a session that arrives without one is redirected rather than served. **That
sentence used to end "so the page writes at most once per half-finished sign-in", and it was
a bound measured on one cookie rather than a property of the route. The tenth round below
shows what it missed and what now makes it true.** Beside it sat a second hole the same fix
exposed: `enrol_page` alone did not check the session epoch, where both its siblings do, so
a password change or a factor reset stopped the sign-in completing while this page went on
serving it fresh secrets and writing them to the record. That is a half-authenticated caller
writing to the credential store after revocation, which is the case the `may_sign_in` check
on this route was added to close one round earlier; that fix swept the disabled and locked
half and left this one open.

**Six of the round's forty-three mutants survived, and each is accounted for rather than
left as a number.** Two are equivalent mutants: dropping either guard in
`pending_secret_for` on its own leaves the comparison returning the same answer, because an
empty stored token still fails `compare_digest` against a real one and an empty request
token still fails against a real stored one. Only dropping BOTH is dangerous, since
`compare_digest("", "")` is True, and reaching that needs a record hand-edited on the volume
to hold a secret with no token, which no code path produces. One is unobservable by any
functional test: replacing `compare_digest` with `==` changes no verdict, and that is why the
docstring there now says the comparison is not a boundary control. Two are the second layer
at the POST, already recorded in `finish_enrolment` as reachable and not exploitable: making
`enrol_submit` pass the STORED token, or `finish_enrolment` ignore the token entirely, cannot
be exploited because the GET has already replaced any secret whose token does not match, so
the caller cannot produce a code for it. The sixth mutated a line that no longer exists,
`reset_factor`'s own call to `clear_pending_enrolment`, deleted a commit earlier as redundant
with `bump_epoch`.

**One control was added in the same commit as the hole it closes and arrived uncovered.** The
coverage report put lines 458 and 459 of `views/auth_routes.py`, the refusal that replaced
the minting, in the missing list on the run that otherwise passed. It is held now by
`test_a_pending_sign_in_carrying_no_enrolment_token_is_sent_back_to_the_start`, proved red by
deleting those two lines: 200 where 302 is required. Writing it down because the pattern is
this build's own: a control that is correct today and unheld is one edit from being wrong.

**Three MINORs, all of them a record reaching further than the code.** `recordable`'s
docstring said it covered "the source address, the user agent, and the one `resource_id` on
the sign-in refusal path. Those three, and no others", and two shipped documents repeated
it. It covers three FIELD NAMES, and the `resource_id` one is every event `record_event`
writes: authentication, account administration and the boot break-glass unlock alike. Most
carry a username the account boundary has already narrowed; the boot unlock carries
`BOOTSTRAP_ADMIN` straight from the platform environment, which nothing narrows, so that
entry genuinely can name its subject `unrecordable`. The enrolment token was called "a
bearer value" when it never leaves a server-signed cookie a caller cannot write. And the two
accepted-residual rows above carried figures from the code as it stood before this round.

**The tenth round repriced the ninth round's MAJOR rather than finding a new one, and that
is the more useful outcome.** The enrolment page's writes were bounded for one captured
cookie and the record claimed they were bounded full stop, in five places: this file, two
accepted-residual rows, and two code comments in the past tense. The decision that mints or
reuses asked whether the ACCOUNT's stored token belonged to this session, and an account's
token is shared state, so two half-finished sign-ins on one unenrolled account took it back
from each other on every load. The gate measured 50 alternating loads buying 50 secrets and
50 staged, fsynced rewrites of the credential store at 450 a second, for two password
verifications, with no audit entry behind any of them; reproduced here at 460 a second
before anything was touched. Nothing is disclosed and no second factor is stolen, which was
checked in both orderings. What it costs is availability, under the one lock every sign-in
and every administration route takes, plus a half-authenticated caller writing to the
credential store at request rate.

**The bound was made per session, and the eleventh round defeated it in one line.** The
reasoning was that the account cannot distinguish "this sign-in has never minted" from "this
sign-in minted and somebody took it", and those need opposite answers, so one bit went on the
session. The bit lives in a cookie the SERVER sets, and a client that never carries the
cookie back never presents it: two pre-mint cookies replayed alternately from fresh clients
gave 50 secrets and 50 writes again, from two password verifications. **A bound held in state
the caller holds is not a bound**, and that sentence cost three rounds. The fix, and what
replaced all of this, is in the eleventh round below; `ENROLMENT_MINTED_KEY` was added here
and deleted there.

**The round's MINOR, fixed for the same reason the MAJOR's record half was.**
`abandon_second_factor` popped the pending marker and its clock and left both enrolment keys
behind, while its docstring said it forgets a half-finished sign-in. Nothing could be built
from the residue, and the gate said so plainly: a surviving token can only match a secret the
same session planted, `pending_actor` returns None so no second-factor route proceeds, and
the next `begin_second_factor` clears the session outright. It is fixed anyway, because a
docstring reaching past its code is what this release keeps being caught for. The epoch
deliberately stays, and the docstring now says which keys go and which does not.

**The eleventh round defeated the tenth round's fix in one line, and the line is worth
quoting: do not carry the server's cookie back.** The bit deciding whether a sign-in had
already minted lived in the session cookie, so two pre-mint cookies replayed alternately
from fresh clients never presented it. 50 loads, 50 secrets, 50 fsynced rewrites of the
credential store at 383 a second from 0.89 seconds of password hashing, with a legitimate
administration write going from a 6.3 millisecond median to 14.5 beside it. That is the
eighth round's figure unchanged after two fixes aimed at it; reproduced here at 431 a second
before anything was touched. Seven statements across the code, the tests and two shipped
records had asserted the bound as a property of the route when it was a property of a
cooperating client, which is the tenth round's own finding arriving one round later against
the author who wrote it down.

**So the page stopped writing.** The unconfirmed secret is now a keyed derivation over the
account name and the random token `begin_second_factor` already puts on the session, under
the application's session signing key with an explicit label. The page recomputes it on
every load, writes nothing and takes no lock; the single write happens on the
CSRF-protected POST by a caller who has proved possession of a code. Measured at zero writes
across 50 loads driven three ways at once, including the cookie-discarding replay that
defeated the last fix. **A bound held in state the caller holds is not a bound**, and that
sentence is recorded at the derivation because it cost three rounds to buy.

Three things that needed controls became arithmetic. Two half-finished sign-ins cannot
derive the same secret, so the ownership comparison, the shared field it compared and the
clause recorded beside it as reachable-and-not-exploitable are all gone with the state. A
reload derives what was scanned. And a password change or a factor reset still ends an
in-flight enrolment, through the epoch on the pending marker rather than by clearing a
field. The enrolment-denial residual closed with them: an attacker can no longer displace
the owner's secret, because it does not depend on anything the attacker can reach.

**And it opened a factor replacement, which an existing test found and which was measured
before it was closed.** Confirming used to clear the stored unconfirmed secret, and that
clearing was the only thing refusing a second pass through `finish_enrolment`, because
`enrol_submit` never checked `is_enrolled`. The docstring of the test that held the clearing
said so in those words. Removing the state inherited its dependency on it: an attacker
holding the password loads the page before the owner enrols and keeps the secret it is
shown, the owner enrols, the attacker POSTs a code that still derives from its own session
token, and the owner's confirmed factor was replaced by the attacker's with a live session
on `/api/registers`. `is_enrolled` now rides with `may_sign_in` in one branch, symmetric
with `enrol_page`, and a test drives the whole sequence. Recorded at this length because the
lesson is not the hole, it is that deleting state silently deletes the guards nobody wrote
down as guards.

The round's two MINORs were controls held by no test, both proved survivors by the gate: the
ordering that set the per-session bit after its save, now moot because the bit is gone, and
`abandon_second_factor` clearing the enrolment keys, now held by an assertion over the
session keys.

**The twelfth round could not break the derivation, and failed the build on a comment.**
It attacked the new code directly: two sign-ins on one account, five interleaved reloads, a
tampered cookie, a forged cookie carrying a chosen token, the key-absence paths in
production, development and scan mode, both orderings of the enrolment race, a second submit
against the recovery codes, and a revocation mid-enrolment. None of it moved. It recomputed
the page's secret outside the process from the configured session key and got the same
value, which proves the key in use is the deployment's rather than a constant. It measured
zero writes across 50 loads driven three ways, with the inode, mtime and content unchanged
and no temporary files left. And it checked the claim flagged as load-bearing, that the
enrolment-denial residual is closed, and found it correct.

**The MAJOR was a comment contradicting its own docstring ten lines above it.** The commit
that rewrote `finish_enrolment` to say the ownership clause had gone with the stored field
left eighteen lines inside the function describing that clause as a live second layer,
reachable, unexploitable and untestable, all of it about a field the same commit deleted. It
is binding in substance and not only by the rule: somebody who believes a second layer
stands there is one edit from removing `enrol_submit`'s `is_enrolled` branch, which is the
branch that stops a confirmed factor being replaced and which has no second layer at all.
The clause is replaced by what the branch means now, and the replacement says why the wrong
version was there, because that is the evidence that the pattern recurred.

**Two of the round's own new controls were held by nothing**, and both were reproduced here
before anything was written. Replacing the whole body of `auth.enrolment_key` with a
constant in the source left every test green: the derived value becomes the account's
permanent confirmed factor, so the server-held key is the only thing stopping anyone with
the source and one captured pre-enrolment cookie computing a victim's live second factor. A
route-level test now recomputes the served secret from `app.secret_key` and the caller's own
session token. Deleting `is_enrolled` from `enrol_page`'s refusal was also green, and it is
the symmetric half of a branch whose POST-side sibling is lethal. Both now die on their own
named assertions.

**And the token's length is recorded for what it buys.** Not stopping a third party deriving
somebody's secret, which the key does and which a guessed token cannot touch; keeping two
half-finished sign-ins from colliding on one token. The constant's comment and the test
asserting it both said otherwise, and that file had already been corrected once for the same
kind of reach.

**A pattern worth stating, and the first version of this paragraph got it wrong in the
direction that flatters.** What it said was that every binding finding since the ninth round
had been a record rather than a missing control, and that "the code survived direct attack
each time". The gate checked that against this project's own table and three of the four
rounds contradict it. The ninth round's two MAJORs were both missing controls: a username the
account boundary accepted and the audit boundary refused, and the enrolment page as a write
amplifier at twelve writes from one password hash. The tenth round's MAJOR was that same
amplifier repriced, still measured at 50 writes from two password verifications. The
eleventh round's PRIMARY MAJOR was the per-session bound defeated in one line of attacker
code, at 50 writes again, and the same round found a confirmed-factor replacement with a
live session on the end of it, which this release had introduced one commit earlier. Only
the twelfth round's MAJOR was purely a record.

What IS true is narrower and still worth keeping: **a record over-claiming has been among
the findings in every round since the ninth**, the prose was written in the same commit as
the change it described, and the author was in every case the one best placed to believe it.
The corrected sentence is left in place of the wrong one rather than the paragraph being
deleted, because the wrong one is the clearest instance of the pattern it was trying to
describe: it was the newest sentence in a shipped, assessor-facing record, it made a claim
about what a gate had measured, and what it told the next reader was to stop attacking the
code, at a commit where a control was held by nothing.

**The thirteenth round read the prose, because that was the whole diff.** Nothing but
comment text had changed, so the gate aimed at the newest sentences in the tree and found
two MAJORs there, with the running service byte-identical to the code it had already
cleared. It also confirmed both of the previous round's new tests lethal and neither
vacuous, including the key test whose shape, an equality it computes itself, was flagged as
one that can be made hollow.

**The first MAJOR is the paragraph above, which is corrected in place rather than removed.**
Its wrong version and the reason it was wrong are kept there, because a record that quietly
fixes its own flattering sentence teaches nobody anything.

**The second is a control described as held when the coverage report said otherwise.** The
comment written to fix the twelfth round's MAJOR ended "and it is held by a test"; the line
had zero hits in the report that had already been read. The branch is also redundant, which
was measured rather than argued: `totp._decode` refuses an empty secret, so without the
branch the call below raises and the handler returns the same `None`. Both facts are now in
the comment. The MINOR beside it was the route's own refusal of a wrong enrolment code, also
never executed, which is a coverage gap rather than the design choice the failure-count
observation is.

Two route tests now hold the compositions that matter rather than the branches: a POST from
a session carrying the pending marker and no enrolment token is refused, confirms nothing
and signs nobody in; and a wrong code is refused at the route. The claim that they cover
those lines was checked by measuring the lines at zero hits before and one after, not by
observing that the tests pass, which is the mistake that produced this round's second MAJOR.

**The fourteenth round is the first security PASS of this release**, and it was reached by
attacking rather than by agreeing. The gate re-drove the derivation, the enrolment
composition, the epoch, the lockout, the role boundary, the security headers and the audit
actor rules itself, having been told that twelve rounds before it had cleared them. Nothing
could be defeated. Five replays of a pre-enrolment cookie produced one secret and no write,
which is the attack that defeated three successive fixes. Asked outright whether the useful
attack surface on the running service is exhausted at this commit, it said yes, and gave its
reasons: the application has been byte-identical through three diffs and everything it drove
held.

**All six findings were coverage or prose, and doing them caught three mistakes of mine that
a passing test would never have shown.** A test that asserted a 302 and got one from the
replay guard rather than the branch it was written for, because enrolment spends the
confirming code. A line number quoted from memory that an earlier edit in the same file had
moved. And a comment describing a state the same commit had just invalidated. Each was found
by measuring the line's coverage before and after, which is now the standing practice for
any claim that a test holds a particular control.

Seven refusal paths are driven that the whole suite had never executed: a lockout landing
between the two factors, which is the only layer for that case because a lockout
deliberately does not bump the epoch and `_pending_refusal` therefore does not catch it; the
AUD-001 lockout entry from the second-factor route; both "no pending sign-in" refusals; both
sign-out paths for a verified identity the log cannot name, which is the attribution gap
this application exists to close; the catch-all that keeps an unavailable LOG from being
treated like an unrecordable ACTOR, so a transient volume fault cannot lock the operator out
of the diagnostics that explain it; and `set_state`'s refusal of a state outside its
vocabulary.

`accounts.is_admin` is deleted rather than given a test. It had no caller anywhere, and a
predicate answering "is this record an administrator" invites the next maintainer to gate on
the record instead of on live standing, which is exactly the defect this release already
fixed when a disabled administrator kept its permissions until the cookie expired.

**The engineering gate found three MAJORs on a build the security gate had just passed**,
which is the whole argument for running both rather than treating one as a proxy for the
other. All three were controls that existed, read as held, and did not do what they said.

**The load-shedding refusal could not fire from any route.** The module header argued a
sign-in flood is bounded because hashing is capped at two concurrent slots and a caller that
cannot get one is shed. Every scrypt call runs while the account-file lock is held, so
hashing was serialised to one, the semaphore could never reach its limit, and callers queued
on an untimed lock: eight concurrent sign-ins ran fully serial with the slowest waiting 4.56
seconds against a three-second budget and nothing shed. The bound is now on the lock, where
the queue forms, and the header states what that buys and what it does not. Hashing stays
serialised at one on the paths the lock covers, so the cost is throughput there. **The
memory ceiling is unchanged at 256 MiB, and this sentence said 128 for one round.**
`absorb_timing` hashes OUTSIDE the lock on the UNUSABLE-username path, and the semaphore is
still two, so six concurrent requests measured two scrypt calls in flight. The re-review
caught it: a figure contradicted by measurement, in the paragraph whose whole purpose is
pod-sizing arithmetic, in the round that exists to correct that paragraph against
measurement, and contradicting `docs/DEPLOYMENT.md`, which said two all along and was
right.

**`needs_rehash` had no caller while two records promised it did**, the header saying an
account hashed under older parameters "is re-hashed on next sign-in" and `hash_password`
promising replacement "on the next successful sign-in". Wired rather than deleted, because
raising the cost as OWASP raises it is the reason the parameters are stored beside the hash
at all, and proven over the route in both directions: a hash planted at a quarter of the
cost comes back current, and an upgrade that cannot run never costs anybody their sign-in.

**The administration blueprint's 503 described a case it never answers.** A signed-in
administrator meeting a corrupt list is stopped by the decorator, which catches the same
error and redirects, measured. The handler still covers the race where the list is readable
when the guard looks and unreadable when the view does, so it is kept and held by a test
that fails the second read; corrupting the file would reproduce the case the guard already
handles and pass without touching it.

**Fixing the first exposed three defects of my own**, and the pattern in them is the same:
each was caught by a deterministic test or by the project's own guards, never by reading the
change. Bounding the three route bodies left `ensure_bootstrap`'s acquire unbounded ahead of
them, so a request could still queue without limit before reaching a shed it would never
arrive at. The budget was a default argument, which binds at import, so `HASH_WAIT_SECONDS`
could not be tuned by an operator or a test: a tunable that cannot be tuned is worse than a
literal, because it reads as a control. And a test asserting `... or True` was written while
removing another one, in a test about boot safety. The loop's architecture ledger then
refused the lazy decoy's new `functools` import until it was declared with its reason, which
is that ledger working as intended.

**Two findings are left open rather than quietly closed.** The three authentication test
modules carry duplicated fixtures and parallel helpers, and the comment density in the
authentication surface has become a record of the review rather than of the code. Both are
refactors across files this release has edited heavily, and they belong in their own change
rather than folded into one that alters authentication behaviour.

**The engineering re-review found five MAJORs in the fixes for the previous three, and
four of them were tests and claims rather than code.** That ratio is the finding worth
keeping. The code defect was one: the rehash's `save` sat outside any `try` while the
comment above it promised the upgrade never refuses a sign-in, so a read-only volume turned
a correct password into a refusal and logged it as a list that could not be read, about a
list that read perfectly.

The other four were all assertions of the form "this is held", made by me, each wrong in a
different way. The guard test never reached the guard, because the fixture's hash is current
so nothing was upgraded and the patched function was called zero times. Both shed tests
passed with the route bound reverted, because the bootstrap variable is set in the fixture
and the shed fired somewhere else entirely: they held a configuration that does not ship.
The busy-versus-unreadable test asserted an action and an outcome that both handlers write
identically. And the memory ceiling corrected in the round before was itself wrong, measured
here at two concurrent hashes and therefore 256 MiB, putting two shipped records into
contradiction when one of them had been right all along.

**What separated the tests that hold a control from the tests that pass beside it was
mutation, every time.** All four were green before and after the thing they name was
deleted. Each of the three surviving mutants is now proved dead, and the busy one dies with
the false record visible in its own output: "could not be read: the sign-in service is
busy".

The export assertion is worth its own line, because it has now been wrong twice. It read
`... or True`, which could not fail; the replacement fetched the export a second time and
fell back to `or {}`, so a non-JSON answer would have satisfied it silently. The same
vacuity through a different door. It asserts the response is an object first, and tests that
object.

**The security gate re-reviewed the engineering fixes and found two MAJORs, neither of them
a bypass.** It went at the two genuinely new surfaces: the first write to the credential
store on the sign-in path, and a refusal an unauthenticated caller can reach. The write held
under direct attack. It cannot be driven without the password, a duplicated form field
cannot split what was verified from what is re-hashed, a write fault leaves the old hash
intact and verifying and counts no failure, and the row is request-local so no later write
can persist a half-updated one. The shed is not an enumeration oracle: the lock is taken
before the account is looked up, so a present account, a wrong password and an absent
username are identical in timing, body and stored state.

**What failed was a guard held by nothing and a figure contradicted by measurement**, which
is the shape most findings in this release have taken. The guard on the rehash `save` was at
zero coverage for a second consecutive round while being asserted as held, and the mutant
that deletes it now dies with the defect in its own output: a write fault reported to the
operator as a read fault, refusing a correct password. The per-caller bound in
`docs/DEPLOYMENT.md` was wrong by about twice, because the lock wait and the hashing-slot
wait are separate budgets that stack while the hash runs under the lock.

**One MINOR was a live defect this release created.** `needs_rehash` compared parameters for
inequality, so a hash made under STRONGER parameters counted as stale and one successful
sign-in rewrote it down to today's. The gate planted `n=262144` against `SCRYPT_N=131072`
and watched it become `131072`. The realistic trigger is a release rollback after the cost
is raised, which is the one operation this storage format exists to survive. It was inert
for as long as the predicate had no caller and went live the moment the previous round wired
it, which is the second time in two rounds that wiring something dormant exposed a defect
that had been sitting harmlessly unused.

**An availability cost is accepted with its measurement rather than fixed.** 16
unauthenticated connections at 3.1 requests a second take the dependency-free `/livez` to
3.19 seconds against this image's 4-second `HEALTHCHECK`, and refuse a correct-password
sign-in at 7.50 seconds; at 8 connections nothing moves. The remedy that bounds it is one
deadline per request shared by both waits. It is named in the code, in the deployment record
and in the residual, and not taken, because it would be a third change to this concurrency
path in one release and the previous two introduced three defects between them. That is a
deferral with the evidence attached, and it is the ISM's to overrule.

**The engineering gate's second re-review found three MAJORs, and every one was a fix that
landed in the code while the test meant to hold it did not.** That is a different failure
from the previous rounds, where tests passed for the wrong reason: here the behaviour was
right and the suite could not tell. Reverting the downgrade comparison left all 1645 tests
green, because the two assertions on the predicate covered the two directions that hold
under either version. The busy clause on the boot path had every statement at zero hits.
And a one-word contradiction survived between two shipped records, in the paragraph about
two shipped records contradicting each other.

**It also found the downgrade fix blind on an axis.** `n * r * p` tracks scrypt's work and
not its memory, so `n=65536, r=8, p=2` and `n=131072, r=4, p=2` carry today's work at half
the memory and read as current. Both axes are compared now, verified across five parameter
sets. Dormant only because nothing but `SCRYPT_N` has ever moved here.

**One repaired test is worth naming, because it was failing for the wrong reason rather
than passing for one.** The first-run shed test killed its mutant by deadlock, not by its
assertions: a 302 and a 401 are both produced by a successful first factor too. It now
asserts the destination and the logged reason, and is proved against a mutation that
satisfies both original checks.

**The availability deferral was accepted, with its record corrected in three ways.** The
gate agreed that CLAUDE.md binds this build to record, own and measure an in-model finding
rather than to fix it inside one release, and that a third change to this concurrency path
carried more risk than the residual, the previous two having put three defects into the
tree. What the row got wrong: it named `/livez` where the HEALTHCHECK polls `/readyz`, so
the measured 3.19 seconds is a floor rather than the figure; it omitted `--retries=3`, which
decides whether an excursion is a restart; and it named one remedy as though it were the
only one, when halving a single constant would halve both budgets at no review risk. The
acceptance is now explicitly void if the platform probes tighter than this image.

**The engineering gate's third re-review closed all three previous MAJORs and found one
new, and the new one is a pattern rather than an incident: half of a symmetric control.**
The separation between a capacity event and an unreadable volume exists in two places. The
clause on `/account/password` carries a comment saying "Same reasoning as the sign-in
route". The sign-in side was held by a test; this side was at zero hits, survived deletion
across 207 tests, and without it a hashing-capacity event tells the operator "The account
list could not be read. An operator should check the volume." about a volume that is
healthy.

That is the third time in this release the defect has been the half not looked at rather
than the half fixed. `enrol_page` once gained a check its sibling did not; bounding three
route bodies left `ensure_bootstrap` unbounded ahead of them; and now this. Worth recording
as a habit to break rather than as three unrelated findings.

**The sharpest finding was a MINOR, and it was algebra.** The work disjunct added to
`needs_rehash` one round earlier cannot fire while `SCRYPT_P` is 1: today's work factor
equals today's memory factor, and every stored set has `p >= 1`, so memory being current
implies work being current. A branch written to close a demonstrated gap was dormant by
construction, which no amount of running the suite would have shown. It is driven now by
raising the parallelism, which is the one parameter movement that separates the two axes,
so it is held against the day somebody makes it live.

**And one record said measured where it meant reasoned.** The availability residual claimed
every correct-password sign-in on a degraded volume runs two hashes; it is only true for an
account whose stored hash is stale, because the upgrade returns before hashing otherwise.
Corrected, with its provenance named, which is the distinction this release keeps having to
learn.

**The fourth engineering round was asked to hunt a class rather than clear a diff, and
that is the part worth keeping.** Three rounds running, the finding had been half of a
symmetric control: a check one route had and its sibling did not, three bodies bounded while
a fourth acquire sat unbounded ahead of them, a clause held on one blueprint and not the
other. So the gate was pointed at the whole authentication surface with one question, where
do two call sites, two blueprints or two except clauses implement one decision, and is each
side held. It returned three more instances and one false claim.

**The sharpest finding is about how this project tests, not about a line of code.** Both
`OSError` conversions in `accounts.save` were at zero hits, and the cause is that the one
place in the suite where a write fault is driven stubs `accounts.save` itself, at
`tests/test_local_sign_in.py:1259`. The conversion inside it had therefore never executed,
which meant no mutation of those lines could ever be caught: a guarantee rather than an
observation. An earlier version of this paragraph said EVERY write-fault test stubs it,
which generalises from a set of one; the conclusion holds and the quantifier did not.
Narrowing the tuple turns a recorded refusal into a 500 with no audit entry on a route an
unauthenticated caller reaches. Both are driven now with a real `OSError`, and the cleanup
beside them is held too, because a fault between staging and renaming must leave no
`.accounts-*` file carrying password hashes behind.

**One finding was a label rather than a control, and the distinction mattered.** Four of
the five `accounts.save` call sites on the sign-in blueprint are unguarded, so a read-only mount
raised from a WRITE and the handler reported that the list could not be READ. The refusal
itself is correct and stays: the save it follows persists the spent one-time-password step,
and granting a session without it would make that code replayable. What was wrong was that
on a mount where nobody can sign in at all, the single error line an operator has
contradicted itself inside one sentence. The handler now says "reached" and lets `load` and
`save` name the direction. **The rewording then emptied one of the three assertions that
depended on the old phrase, and the fifth engineering round caught it.** See below; the
sentence that used to sit here claimed the three had been checked, and they had not.

**And a claim written in the previous commit held nothing.** A docstring said asserting both
halves pinned the order of two exception clauses; a mutant swapping them left it green,
because it drives the error that lands in the generic branch either way. Corrected and
attributed to the sibling that does hold it, rather than reworded, since a claim that holds
nothing is what that commit existed to stop shipping.

**The fifth engineering round is the one that ends this release, and it ends it by showing
that a fix of mine broke a control rather than by finding a new defect.** The reword above
moved the fault handler's message from "read" to "reached". The single assertion separating
a shed sign-in from an unreadable volume was keyed on the word "busy" being present and
"could not be read" being absent, and BOTH handlers end in `_refuse` and interpolate the
error into their log line. So after the reword a shed falling through to the fault handler
still said "busy", and the dead phrase could no longer appear whichever handler fired. The
gate removed the busy handler outright and the whole suite stayed green, then proved the
same mutant red against the pre-reword wording: a regression created by the fix, not a gap
the fix inherited. Both phrases now assert on something exactly one handler emits, "shed
under load" and "could not be reached", and the second is pinned positively by the
corrupt-file test, which is the path that legitimately produces it. Two sibling assertions
keyed on the same dead phrase were re-keyed with it.

**The round also found four false statements in the two shipped records, three of them
written by the round before.** The sign-in blueprint has five `accounts.save` call sites and
one guard, not four and one: the "four" was the `accounts.load` count, correct for reads and
transplanted onto writes. One test stubs `accounts.save`, not every write-fault test in the
suite. And the claim that the three dependent assertions had been checked against the
rewording was false in the specific way that mattered, since one of them had been emptied by
it. All four are corrected above and in `docs/GATE-RECORDS.md`. Seven over-claiming records
in this release were found in shipped documents; these were found in the record of the gate
round that found the others, which is the honest place to say the habit belongs to the
project and not to one document.

**What is NOT fixed, and the reason is a decision rather than an oversight.** The same
read-versus-write mislabelling is still live on `account_bp`: a write fault answers an
authenticated administrator "The account list could not be read." while the log one line
away says "could not be written". It is a wrong operator-facing string on the administration
half, behind authentication, with no security consequence, and correcting it would empty
five further assertions keyed on the old phrase in exactly the way described above. It is
recorded as accepted residual with its measurement, alongside the bare `raise` at
`accounts.py:614` and the duplicated stored-hash helpers, rather than carried into another
gate round. Twenty-one gate rounds have run against this release and one returned PASS; the
application has survived every direct attack since the third security round, and what the
last four rounds found was test-holding and record wording. Stopping here is Ash's decision,
taken with that record in front of them.

**Deviations open at this release.** The audit-chain deviation from AUD-001, unchanged.
And now AMD-001 section 10.4, which names Entra ID: two factors are still required on every
sign-in, so the clause is met substantively and not literally. Both are Adam Field's to sign
off. `docs/ACCREDITATION-REVIEW.md` carries the re-accept action.

**One thing this repository cannot check, stated rather than implied.** Local accounts
outlive an employment unless somebody disables them. The argument that this does not matter
is that the App Store requires an active Entra ID in the Bluestaq tenant for access, so a
former employee cannot reach the application at all. That holds only while
`directive.apps.bluestaq.com` is behind the same gate as the App Store portal, which is a
platform configuration: `TBC, re-verify` with the platform team.

## V2.4, 2026-11-05, `b4cdd2e` and the version bump that should have come first

**Why this release exists.** V2.3 was uploaded to the App Store three times and rejected
three times, and every fix went out still stamped 2.3. Four distinct packages carried that
one version, from four different commits. The platform shows an operator only the version,
so three of those were uploads of a "2.3" that was not the 2.3 before it. Nothing in the
build objected, because the archive filename carries the commit and every build therefore
found a free name. That is the first thing fixed here, and it is fixed in the build rather
than in a habit: `build-package.sh` now refuses to package a version it has already
packaged from a different commit, and names what to do. Two tests hold it, one in each
direction, because a guard that also blocked an ordinary rebuild would be switched off
within a week.

**Fixed, the three App Store pipeline failures.**

● **Stage 5 ran a different command from the simulation.** `pytest` as a console script and
  `python -m pytest` are not the same: `python -m` puts the working directory on
  `sys.path`, the console script does not. The App Store runs the console script, so
  `import wsgi` resolved locally and failed there. Both `verify.sh` and
  `simulate-pipeline.sh` used `python -m`, which means the pipeline simulation ran a
  different command from the pipeline it simulates and reported PASS on a tree stage 5
  rejected. A simulation that is believed and wrong is worse than none. Both now run the
  console script, and `conftest.py` puts the project root on the path, so the suite is
  correct under either command.
● **The dynamic security scan got no answer.** It runs the image with NO environment
  variables and this application refuses to boot without Entra ID and without
  `SESSION_KEY`. Both refusals stay. `auth.scan_mode()` honours the platform's
  `APPSTORE_DAST_SCAN=true` ONLY while Entra is unconfigured, so it cannot degrade a
  deployment that has an identity provider, and nothing after boot is relaxed: the session
  cookie keeps its `Secure` flag and the self-asserted sign-in is refused in that mode
  exactly as it is when Entra is configured. That last clause is load-bearing, because the
  sign-in path is gated on Entra being CONFIGURED and without it the boot relaxation would
  have handed the scanner a signed-in session.
● **The container scan rejected 15 critical and 145 high**, every one an operating-system
  package from a base image digest four CVE-months old, the interpreter among them at
  3.12.14 against a fix in 3.12.16. Re-pinned to the current `python:3.12-slim`, which is
  3.12.16. Nothing local can see this class, so the pin now carries its date and says to
  re-pin when it is over a month old.

**Fixed, a test that measured the runner rather than the code.** The export orphan test
required a mutator thread's first POST to land within twenty milliseconds, which is less
than one durable `fsync` on a container volume. Reproduced here rather than reasoned about:
pinned to a single CPU the old code reproduces the platform's exact message about one run
in three, and the new code passes five of five. Both properties it needs are now
established by waiting rather than assumed.

**Fixed, five dependency advisories that opened since September**, `werkzeug` among them,
which ships. The other four are dev-only. Found by re-running the loop, which audits
against live advisory data, so a lockfile clean in September was not clean in November
without anyone touching it.

**Changed, the platform quality report answered.** Two bugs, three security hotspots and
most of the code smells. Three findings were refused with reasons rather than applied, and
those are recorded in `docs/GATE-RECORDS.md` as well as here:

● **S6353 would have reintroduced a fixed defect.** It asks for `\d` in place of `[0-9]`.
  `\d` is Unicode-aware, so it matches the Arabic-Indic digits, and `int()` parses them.
  The identifier grammar carried `\d` for that reason and a row planted on the volume could
  move the identifier counter.
● **S7924 reported three contrast failures that are passes.** Measured over the composited
  backgrounds rather than the declared `rgba()`: 12.88:1, 11.51:1 and 9.63:1 against a
  4.5:1 floor. The rule reads the declared translucent colour, not what it composites to.
● **S5754 asked for a narrower exception in the storage probe.** `BaseException` there is a
  hard rule in `CLAUDE.md`: a probe never raises and never hangs.

**Changed, the record drawer is a native `dialog`.** The analyser asked for it as a style
note and it closed a real defect: the `role="dialog"` version had no focus trap, so a
keyboard user could Tab out of an open record into the table behind it. Driven in a browser
to check rather than assumed, nineteen checks including focus staying inside across
twenty-five Tab presses with zero leaks.

**Open at this release.** Unchanged from V2.3 and all four belong to their owners: the
Managing Director's sign-off on the App Store target, the four submission fields, and the
`securityContext.fsGroup` and single sign-on exemption requests. The container image has
still never been built or run: there is no Docker daemon in the environment this was built
in, so its non-root user, setuid sweep, absent package manager and single layer are held by
reading and by tests rather than by probing a built image. Every page load 404s on
`/favicon.ico`, which the browser requests unprompted and this application does not ship.

## V2.3, 2026-09-22, `a3741c8` and the fixes that follow it

**Gates.** `deploy-gate` **FAIL** at `a3741c8`, on five blockers: neither binding review had
seen the tree, the Managing Director's sign-off was outstanding, four required submission
fields had no value, the signed accreditation described a three-register application while
the package shipped five, and the version had not moved since 2026-09-10 although 1,778
lines had. `security-reviewer` **FAIL** at `a3741c8`, two MAJORs and two MINORs, every one
in application code rather than build machinery. It held the generated form against five
cross-site scripting payloads, the drawer's patch path against missing and wrong tokens,
referential integrity against traversal and oversize values, and the Article 28(2) invariant
against six routes, and it proved eight of nine new controls by deleting them.

Both gates then returned **FAIL** again at `f2e12f8`, the commit that answered them, and
both were right. The version bump had disarmed the test holding the packaging version
guard, so the verification loop was red and, under `set -eu`, the dependency scan, the bill
of materials and the lockfile nesting legs never ran. That commit's message asserted a pass
count measured against a different tree, which is the rule the two previous FAILs were
about. Three shipped records were wrong. And the security gate found that a complete
transfer risk assessment could not be created at all. Every row, with what each gate found,
is in `docs/GATE-RECORDS.md`. A third round at `896ee9f` then took the security gate to
**PASS** and the engineering gate to **FAIL** again, on four MAJORs: an identifier grammar
tightened and held by no test, a comment stating a superseded figure, a deviation row in
`docs/DEPLOYMENT.md` still recording the old cap, and the OWASP note describing a fix that
was explicitly not the one taken. A fourth round closed those and returned one MAJOR
and six MINORs, the MAJOR being a blank line that had been relocated rather than removed
and so still split the gate table. A fifth round closed the
MAJOR and returned four more with three MINORs, every one in a shipped record: two counts
the tree does not support, a positional claim about a table a later insertion had moved, and
a table split by prose. A sixth then found that the test written to close that class did not
close it, and named four rows losing content to an unescaped pipe that no reading had
caught. Not one finding across any of those rounds was in the running application's
security controls. The register fixes held under mutation, the Article 28(2) invariant held
on six routes to APPROVED, and the 27-check evidence record reproduced independently.

**Changed.**

● **Fields have a KIND.** Text stays capped; a date is an ISO calendar date; a choice is a
  closed vocabulary; a link names a record in another register. Field acceptance is scoped
  to the REGISTER rather than the application, so a task cannot carry a transfer agreement.
  Until this release the application held a compliance operating rhythm with no concept of
  when anything was due, and a risk register with no severity.
● **Two registers for the restricted transfer.** `agreements` holds the International Data
  Transfer Agreement and records the controller, exporter, importer and the importer's role
  from a closed vocabulary. `transfers` holds the Transfer Risk Assessment and REQUIRES the
  agreement it assesses; a link to an agreement that does not exist is refused rather than
  stored.
● **UK GDPR Article 28(2) is held by the application.** A transfer assessment cannot reach
  `APPROVED` while the controller's authorisation is unset or `NOT_OBTAINED`, and the
  refusal names the article and says what to record. First rule in this build that reasons
  about a record as a whole rather than field by field.
● **The console generates its form from the schema**, so a field added to a register appears
  without a second edit, and a record opens in a drawer where every field is readable and
  editable. Before this a record was write-only: the interface could not create a transfer
  assessment at all, because `agreement` is required and no form offered it.
● **The application is renamed to Directive**, slug `directive`, package `src/directive`,
  environment prefix `DIRECTIVE_ENV`, host `directive.apps.bluestaq.com`.
● **The audit boundary caps a field NAME, and its total cap is measured.** At a
  128-byte total, a transfer risk assessment naming all thirteen of its declared fields and
  a starting state joined to 132 bytes, so the audit boundary refused the entry and the
  create answered 400: the flagship register could not be created in full at all. Found by
  the security gate, and it survived because nothing exercised the register declaration
  against the audit cap; the console cannot reach it either, since the create form renders
  the required fields only.
  The obvious fix was wrong and is worth recording. That 128 was itself a deliberate
  tightening from 512, made to stop record content wearing a field name's clothes, so simply
  raising the number would have undone a privacy control to fix an availability one. The
  sentence that tightening was aimed at is 79 bytes: it passed a 128-byte TOTAL cap on its
  own and was only ever caught when doubled. A total cap was always a proxy for a rule about
  each NAME. So the per-name cap is now explicit at 48 bytes, which refuses that sentence at
  the first occurrence and keeps refusing it however many fields a register grows, and the
  total is 256, which carries only what it claims: no single entry dominates the log. The
  longest name any register declares is `data_categories` at 15 bytes. Both figures are held
  by tests measured against the registers rather than asserted.
● **The shipped records caught up with the five-register reality**, which was a deploy-gate
  blocker in its own right. `README.md` describes what the application holds. The OWASP Top
  10 record carries a V2.3 addendum of 27 checks actually sent against the two new registers,
  27 passed, with two observations recorded rather than closed: a refused state transition
  writes no audit entry, and the Article 28(2) invariant reads the assessment's own
  authorisation field rather than the linked agreement's importer role. The accreditation
  record carries a re-review addendum, drafted and deliberately unsigned, naming which of the
  seven AMD-001 10.4 confirmations this release touches. `docs/DEPLOYMENT.md` names all five
  state vocabularies rather than the first three.

**Fixed.**

● **A no-op update wrote a permanent audit entry.** A double click on a state button put an
  immutable signed row with an empty `fields_changed` into the evidence an assessor reads.
  The test that should have caught it asserted the weaker property that the entry claimed no
  transition, which was true of the defect.
● **Every agreement was issued the identifier `IDTA-0001`.** `next_id` matched rows against
  a three-letter prefix pattern, false of the four-character `IDTA`, so no existing record
  ever matched. Three controls failed together: the audit entry's `resource_id` named the
  same record for all of them, only the first could be read or corrected, and a transfer
  assessment's link passed referential integrity against an identifier naming several
  different agreements.
● **A date was coerced rather than rejected.** `date.fromisoformat` accepts the whole ISO
  8601 grammar, so `2026-W01-1` was stored as `2025-12-29`, a year earlier than typed, on
  the review date an assessor reads. Combined with the no-op guard it returned HTTP 200 and
  wrote no entry at all. This broke the hard rule that a field is rejected at the boundary
  and never coerced.
● **A required field could be emptied by a partial update.** The requirement held at
  creation and gave no protection afterwards, so a title could be blanked and the record
  left with no name in any list an assessor reads. `agreement` was not exposed: its link
  format rejects an empty string first, so it survived by accident rather than by design.
● **A shipped table's STRUCTURE is now held by a test.** Three ways a table silently does
  not render as written, each found here. A blank line terminates it, so a row below one
  becomes a paragraph of literal pipe characters. A row with the wrong cell count loses the
  columns it does not reach, or has its excess discarded. And an unescaped pipe inside a
  code span splits the cell there, so the rest of the row vanishes from the render while the
  source still looks complete. That last one was dropping the tails of four V2.2 gate
  verdicts and about 3,200 characters of one residual row, in the document an assessor reads
  to see what each binding gate returned. Nothing in the source looked wrong.
  Be exact about what is held, because the first version of this test claimed to close the
  class and did not: it read only lines beginning with a pipe and only the first two lines of
  a run, so it was green with two broken tables in the tree, one of them inside the very
  table it was written to protect. What is held now is structural, and only that: header and
  delimiter, cell count, closing pipe. A row can still say something false in a well-formed
  cell and no test here will notice.
● **The issuing half of the identifier grammar was inert.** `next_id` matched `[0-9]` and
  reverting it to Unicode-aware `\d` left the whole suite green, while its sibling in the
  LINK grammar was pinned, so a test naming the parity of the two halves as its reason could
  only ever fail on one of them. The difference is real: `int()` parses non-ASCII digits, so
  under `\d` a row planted on the volume with Arabic-Indic digits counts as a used number
  and moves the counter. A writer on the persistent volume is the adversary `SECURITY.md`
  names and the accreditation carries as a condition.
● **Verification could raise instead of returning a verdict.** An entry whose `key_id` is
  unhashable, a list or a dict, made the key lookup raise `TypeError` and verification exit
  by exception. The journal's loader type-checks every field before it builds an entry, so
  nothing untrusted reaches it, and it is fixed anyway: "a verdict, never an exception" is
  stated with no reachability caveat, the two hash columns beside it were already hardened
  against the same shape, and an unreachable path is one refactor from being reachable.
● **A tightened identifier grammar was held by no test.** The LINK format gate moved from
  Unicode-aware `\d` to `[0-9]`, so both halves of one identifier grammar agree, and the
  whole suite stayed green with the tightening reverted: every existing test sent a
  well-formed identifier, which passes the format gate and dies a layer later at
  referential integrity, so the refusal line never executed. Third finding in a row about a
  control left unheld, which is the pattern rather than the incident.
● **The version bump disarmed the test holding the packaging version guard.** The test
  pinned the literal `version = "2.2"` to spoil the manifest, so bumping to 2.3 made the
  line a no-op and the test died on git's exit code rather than on the control. The guard
  in `scripts/build-package.sh` was left held by no passing test, and the verification loop
  was red. The version is now read out of the manifest and the substitution is asserted to
  have bitten, so the next bump cannot orphan the probe again.

**A note on the figures in this file.** Every count and percentage here was measured on the
tree it describes. Two were not, earlier in this release, and both were caught by a gate: a
pass count taken from a run against a different tree, and a coverage figure truncated from
one run and quoted against another. `docs/GATE-RECORDS.md` carries both. The rule in
`CLAUDE.md` is to measure a figure before asserting it, and this release broke it twice
before it held.

**Open at this release.** The Managing Director's sign-off on the App Store target. Four
submission fields: visibility, category, short description, full description. The
`securityContext.fsGroup` and single sign-on gateway exemption requests. The container image
has never been built or run, so its non-root user, setuid sweep, absent package manager and
single layer are held by reading and by tests rather than by probing a built image.

**A note on the commit references in this file and in `docs/GATE-RECORDS.md`.** History was
rewritten on 2026-09-13 to excise two policy instruments from it, at the owner's
instruction. Every commit identifier recorded before that date names an object that no
longer exists in this repository. The verdicts are unchanged and the records are otherwise
accurate; the identifiers are not resolvable and should be read as naming the pre-rewrite
lineage.

## V2.2, 2026-09-10, `ee7a1e1` and the packaging change that follows it

**Gates.** Recorded in `docs/GATE-RECORDS.md`, with the commit each ran against. Security
review PASS at `b3b798c`, then a run per fix against the packaging and verification
machinery, recorded row by row in `docs/GATE-RECORDS.md`, every one of them FAIL and every
finding in that machinery or in a shipped document rather than in the application. Deploy gate **FAIL**, first run, at `ee7a1e1`.
Engineering review **FAIL** at `c4a33cf`, on the Continuous Integration bill of materials
still describing the pre-split dependency tree and on a test count in this file that had
never been measured. The verification loop is red at some commits of this release and green
at others, and `docs/GATE-RECORDS.md` carries the commit, the verdict and the findings for
each gate run. THIS PARAGRAPH carries no test count and no coverage figure, because a
figure describing a tree does not belong in a release note: this one has carried a wrong
count three separate ways, most recently in the commit written to stop exactly that.
`docs/GATE-RECORDS.md` does quote them, in the V2.2 rows and the V2.3 rows alike, because in
both releases a figure was itself the finding. Be exact about the scope, because this
sentence has now been wrong three times: it first claimed the whole file carried none, the
correction then claimed the V2.2 rows carried none, and the correction to THAT said seven
counts and a coverage figure when those rows carry fourteen count mentions and two coverage
figures. No number is asserted here now, which is the only version of this sentence that
cannot go stale. The sweep-cost figures in this
file are read back by `tests/test_sweep_cost_figures.py`. The others are measurements
recorded at the time they were taken, and they are not read back: the 82 pre-deployment
checks, the image layer count, and the refusal-flood sizing. Saying more than that is how
this paragraph has been wrong four times, twice in the sentence written to fix the last
one.

**Changed.**

● Multi-factor authentication is enforced by the application. `claims_from_id_token`
  refuses an identity token whose `amr` claim is not a list containing `mfa`, so a
  Conditional Access policy that is scoped down, excluded for an account, or bypassed
  produces a refused sign-in and a `LOGIN_FAILED` row rather than a verified actor on the
  audit log. AMD-001 section 10.4.
● The dependency lockfiles split three ways: `requirements-runtime.txt` for the image,
  `requirements.txt` for the platform's test stage and dependency scan, `requirements-dev.txt`
  for the local loop. The previous single-file shape could not have deployed: the platform
  runs `pip install -r requirements.txt` then pytest, and a runtime-only file fails that
  stage with every later stage skipped. The three nest at the `.in` level and the subset
  relation is asserted by the loop and by the suite.
● `scripts/build-package.sh` and `scripts/simulate-pipeline.sh`. The artefact that would be
  uploaded had never been built or tested; both failures found by running it are now
  assertions in the build script.
● The credential sweep over the staged package, and the matching pre-write hook, catch an
  UNQUOTED assignment. Every secret this application consumes is written without quotes, so
  the previous rule covered none of them: an unquoted client secret in `.env.example` built
  clean and shipped at the package root. Several gate rounds went into the pattern set, each
  of them demonstrating a shape that still shipped. It now matches an assignment at the
  start of a line behind any `ENV`, `ARG`, `export`, `-e`, `--env` or list-marker prefix at
  any indent and behind an optional quote or backtick; the same assignment anywhere in a
  line of prose; and a credential-shaped token in any cell of a document parameter table
  row. Everything compiles with MULTILINE, and with IGNORECASE except the prose rule,
  which must not fold case. Without MULTILINE the anchored
  rules matched only at the first byte of a file and a UTF-16 credential below line one
  shipped. The live rules produce 1 finding across every tracked file, and it is the
  declared test double the exemption ledger pins by path, digest and match count. What is
  still
  open is listed under Open in scope in `docs/GATE-RECORDS.md` rather than implied to be
  closed, and the largest item is `NAME = value` with spaces: closing it gives 32 findings
  on 32 lines across every tracked file, the experiment being to replace `=` with
  `[ \t]*=[ \t]*` in that rule alone. The sweep-cost figures in this bullet are asserted by
  `tests/test_sweep_cost_figures.py`, against the live tree and against this sentence.
● The sweep and the pre-write hook are asserted to be one rule set by
  `tests/test_secret_rule_parity.py`, patterns and flags compared character for character,
  with one named exception. Both files claimed to be in step in a comment, and the claim
  was false twice. The same module also EXECUTES the hook against a probe per rule: the text
  comparison alone was defeated by leaving the rule array untouched and iterating only its
  first element, which stopped twelve of thirteen rules blocking with the suite green.
  It now also asserts WHICH fields of a write reach the rules, that a write is scanned
  whatever file it is aimed at and however long it is, that both registration files carry
  the matcher, and that each registration points at a hook that exists and is this one.
  Narrowing the hook's input collection to one field blinded it to every `Edit` and
  `MultiEdit` with the suite green. So did a `file_path` carve-out for
  `.env`, a 400-byte length bound, and a registration pointing at a filename that does
  not exist. Which rules run, which fields are read, what those rules see, and whether
  the hook runs at all are four separate controls, and each was found by a reviewer
  defeating the tests written for the one before it.
● `tests/test_sweep_cost_figures.py` re-measures the three costs that justify the three
  open gaps, asserts the sentences that report them, and sweeps every tracked file for
  anything written in the same shapes. Every part of that was added only because an earlier attempt at it
  closed one and left the next open: the measurement, then the prose reporting it, then
  the files outside the declared three, then the clauses inside a pinned sentence. Every
  figure the module reads back is a digit, because one written as a word is invisible
  to any scanner.
● `tests/test_house_voice_hook.py` executes the house-voice hook once per registered tool.
  Nothing referenced that hook at all, and it had shipped unable to read a notebook write
  while registered for one. Four figures in shipped files
  went stale before it existed, one of them written stale in the commit that measured
  it. A number in prose is an argument nobody can check.
● `.gitignore` refuses `.env.*` with `.env.example` excepted, and the same key and
  certificate family the packaging sweep refuses inside a package. The two controls
  disagreed: an `audit.key` at the repository root was trackable and is outside the package
  allowlist, so nothing downstream would ever have seen it, and the deployment runbook tells
  the operator to generate that key with `openssl rand -hex 32`. No hook sees a human
  `git add`, so the ignore file is the only control on that path into the history.
● `docs/OWASP-TOP-10-TEST.md`, the AMD-001 10.6 pre-deployment test, 82 checks, none failed.
● `docs/ACCREDITATION-REVIEW.md`, the AMD-001 10.4 review. **Signed, accredited with
  conditions**, by Ash Higgins as UK Information Security Officer, 2026-09-10.
● `docs/GATE-RECORDS.md`, so a gate verdict is an artefact in the tree rather than a claim
  in a commit message. Two separate gates failed on exactly that absence.
● The shipped image is one layer again. A `WORKDIR /app` after the flattening `COPY` cost a
  second one; gunicorn takes `--chdir /app` instead. Measured on a real build, 2 layers
  before and 1 after, booting in production mode with the chain intact.
● Rollback for a first release is deletion of the application on the platform, confirmed by
  the ISM. Deletion does not revert the volume, which is the part that matters.

**Deviations open at this release.** Secrets as App Store environment variables rather than
Azure Key Vault. Identity token signature not verified, back-channel only, OpenID Connect
Core 3.1.3.7. Audit entries record field names and never field values. The audit digest is
keyed and chained, stronger than AUD-001's plain SHA-256. No alerting, AUD-001's Application
Insights alerts superseded by the App Store decision, replacement `TBC, re-verify`. Refusal
flood residual of about 202 MiB a day, reaching the audit log's 64 MiB refusal cap in about
7.6 hours under sustained unauthenticated flooding. SBOM short of the CISA 2026 minimum
elements. No CSV exporter for the AUD-001 annual export. No scheduled base-image rebuild.

## V2.1, 2026-08-27, `e45c156`, merged to main at `07270bf`, and `ec75bd2`

**Gates.** Engineering review PASS. Security review PASS at round twelve, after eleven
rounds of findings, each fixed and re-attacked. Verification loop PASS.

**Changed.** The console itself: the task, incident and risk registers on an atomic durable
store; the persistent chained audit journal with its keyed anchor; Entra ID sign-in; the
health and diagnostics paths; the AMD-001 10.6 security headers. Then the refusal collapser
and its bounds, which took rounds seven to twelve: an unauthenticated caller could fill the
audit log to its refusal cap, and each of the first three fixes was measured and found
short of what it claimed.

## V2.0, 2026-08-20, `e1cd87f`

**Changed.** The App Store Python scaffold and the audit hash chain, keyed and anchored,
with the storage probe bounded and `/healthz` registered. No release record was kept at the
time; this row is reconstructed from the commit history and carries no gate verdicts,
because none is recorded.
