# Your bespoke Foundations set

For a server project (Python, App Store template python).

The files in this zip are FLAT (no folders) so GitHub and Claude Code can ingest every one
without a folder upload. Restore the .claude/ tree before you use them.

## Install (two steps)

1. Unzip this at the root of your project (or a new empty folder).
2. Open Claude Code there and paste: "Read REHYDRATE.md and rebuild the layout it maps,
   confirm the .claude/ tree and CLAUDE.md are in place, then read getting-started and follow its
   skills-first gate before you plan or build. Treat the baseline as a fail-closed control:
   security-hardening, packaging, and appstore-gate-compliance are the skills that pass the App
   Store gates, and resource-discipline governs the review cadence."

REHYDRATE.md holds the full flat-to-folder map and the exact prompt. The `__` in a file name
marks a folder boundary (so skills__getting-started__SKILL.md becomes
.claude/skills/getting-started/SKILL.md).

## What is inside

72 files: the agnostic core, the four review gates, the
output style, hooks, settings, CLAUDE.md, and the skills this shape needs.

## Left out (available in the full bundle)

- AI update scan (ai-update-scan)
- LLM integration (llm-integration)

A few included skills mention an omitted one in passing (a "see ..." reference); that is
harmless. If the project later adds a database, a sign-in, or an AI model, download the full
bundle from Code With Bob to pull the matching skill back in.
