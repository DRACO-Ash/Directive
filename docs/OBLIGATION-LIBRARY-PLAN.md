# The obligation library: a build plan

Draft for Ash's decision. Nothing here is built. Written because `README.md` line 2 and the
GitHub description both say this is the core of the application and it does not exist, and
raising that a third time is less useful than making it decidable.

## What it is

A register of the things Bluestaq Ltd is obliged to do, each mapped to the control that
satisfies it and the evidence that proves the control runs. Three sources named in the
description: UK GDPR articles, IASME Cyber Assurance themes, Def Stan 05-138 clauses.

The value is the join. Today an assessor asks "show me how you meet IASME theme 4" and the
answer is assembled by hand from memory, a policy document and a folder. With the library
the answer is a query, and the evidence behind it is the audit log this application already
keeps.

## The constraint that shapes everything

**The no-invention rule binds harder here than anywhere else in the build.**

An obligation library whose clause references are subtly wrong is worse than no library at
all: it produces confident, checkable, incorrect answers in front of an assessor, and the
error is invisible until someone with the standard open contradicts it.

I can recite UK GDPR article numbers and titles; they are public and stable. I am much less
safe on IASME theme numbering, which has changed across scheme versions, and on Def Stan
05-138 clause numbering and its level structure. Getting one digit wrong in a Def Stan
clause is exactly the plausible fabrication the rule exists to stop.

So the architecture has to make it structurally impossible for an obligation to enter the
library without a human-verifiable source. Two consequences:

● **Obligations are loaded from a curated data file, never typed into code.** The file is
  reviewed and signed off in the same way a policy document is.
● **Every obligation carries provenance**: which document, which version or scheme edition,
  which clause, and who verified it. An obligation with no provenance does not load. That
  is the same fail-closed posture the audit boundary already takes.

This is not defensive paperwork. It is the difference between a tool an assessor trusts and
one they stop trusting after the first wrong reference.

## Data model

Four record types. The first is reference data; the other three are Bluestaq's own.

**Obligation.** One requirement from one source.
`id`, `source` (one of a closed set: `UK_GDPR`, `IASME_CA`, `DEF_STAN_05_138`), `reference`
(the article, theme or clause as the source numbers it), `title`, `summary`, `provenance`
(document edition and verifier), `applies_from`.

**Control.** Something Bluestaq does. Some already exist implicitly in this application:
the audit chain, the export cadence, Entra ID authentication.
`id`, `title`, `owner`, `state` (a closed vocabulary as the registers have),
`implemented_by` (free text or a reference to a system).

**Mapping.** The join, and the interesting part.
`obligation_id`, `control_id`, `strength` (one of `MEETS`, `PARTIALLY_MEETS`, `DEVIATES`),
`rationale`. `DEVIATES` is not a failure state; it is the honest one, and
`docs/DEPLOYMENT.md` already demonstrates the pattern.

**Evidence.** What proves the control ran.
`control_id`, `kind` (`AUDIT_LOG`, `EXPORT`, `DOCUMENT`, `ATTESTATION`), `locator`,
`captured`. For `AUDIT_LOG` the locator is a query against the chain this application
already holds, which is what makes the evidence self-proving rather than asserted.

## Why this fits what is already built

Very little new machinery. `records.py` already gives closed-vocabulary registers with
boundary validation, `store.py` gives atomic durable writes under a lock, and every
mutation already writes a chained audit entry. Controls, mappings and evidence are three
more registers on that spine.

Obligations are the exception: they are reference data, not operational records, so they
are read-only in the application and change only by loading a reviewed file. That
separation is worth keeping strict, because it is what stops an operator quietly editing a
GDPR article to make a mapping look better.

## Slices, smallest useful first

**Slice one, the spine.** Obligation loader with provenance enforcement, the Control
register, and the Mapping join. No evidence yet. Deliverable: given a source and a
reference, the application can answer "what do we do about this, and is it met, partially
met, or deviated". Roughly the size of the records module.

**Slice two, evidence.** The Evidence register plus the `AUDIT_LOG` locator resolving
against the existing chain. Deliverable: a mapping can be followed to a specific set of
audit entries. This is the slice that makes the tool worth more than a spreadsheet.

**Slice three, the assessor view.** One page per source, showing every obligation with its
mappings and evidence, and an export in the shape the `evidence-pack-assembly` skill wants.
Deliverable: the thing you hand an assessor.

**Slice four, coverage.** What is unmapped, what is mapped only to `DEVIATES`, what has no
evidence. Deliverable: the gap list, which is the report the ISM actually wants and the one
nobody has time to assemble by hand.

Slices one and two are the build. Three and four are comparatively cheap once the data
model holds.

## What I need before starting

Four things, and the first is the blocker.

1. **The obligation data itself, or a source I can work from.** I will not type UK GDPR
   articles, IASME themes or Def Stan clauses from memory into a compliance tool. Give me a
   spreadsheet, an export, a document, or the scheme's own published list, and I will build
   the loader around it. If a partial list is all that exists, slice one can ship with ten
   obligations and grow.
2. **Whether `DEVIATES` needs Managing Director sign-off** the way the audit deviations do.
   My assumption is yes, and that changes the Mapping record.
3. **Whether the library is per-scheme-version.** IASME editions change; if a mapping must
   survive a scheme revision, obligations need versioning from the start rather than bolted
   on later. That is a data model decision, not a feature.
4. **Whether this is V3.0 or a V2.x addition.** It is large enough to be its own release,
   and the App Store slug and deploy contract do not change either way.

## The honest alternative

If the registers plus the audit log are what you actually needed, and the obligation library
was aspiration rather than plan, say so and I will correct `README.md` and the repository
description instead. That is a five-minute change and it is better than a description that
promises a core the application does not have.
