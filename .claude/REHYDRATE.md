# REHYDRATE: flat bundle to working .claude/ layout

Every artifact here is a single file at one level, so nothing needs a folder upload. The original path is encoded in the filename with `__` as the separator. For example `skills__getting-started__SKILL.md` is really `skills/getting-started/SKILL.md`, and `agents__deploy-gate.md` is `agents/deploy-gate.md`.

You can read or edit any file here directly. To make Claude Code **use** them (skills, agents, hooks and the output style auto-load only from the nested layout), rehydrate once with the matching command, run from inside this flat folder. The full commands are in `START-HERE.md`; the summary is below.

## Naming map

- `START-HERE.md`, `REHYDRATE.md`, `AUDIT.md`, `COMPLETENESS.md`: reference docs, not copied into `.claude/`.
- `CLAUDE.md`: moves to the **project root** after rehydration (it is the project memory Claude Code reads).
- `plugin.json`: rehydrates to `.claude/.claude-plugin/plugin.json` (the manifest must live under `.claude-plugin/`; every other component sits at the plugin root).
- `settings.json`: rehydrates to `.claude/settings.json`.
- `hooks__*` becomes `hooks/*` (the guardrail scripts and the SessionStart skills check).
- `skills__<name>__SKILL.md` becomes `skills/<name>/SKILL.md` (29 skills). A skill may also carry deeper reference files, encoded the same way: `skills__<name>__references__<file>` becomes `skills/<name>/references/<file>` (the first `__`-separated segment is the skill name, the rest is the path below it).
- `agents__<name>.md` becomes `agents/<name>.md` (4 reviewers).
- `output-styles__house-voice.md` becomes `output-styles/house-voice.md`.

## After rehydration

You get the standard tree:

```
<repo root>/
  CLAUDE.md                              project memory, fill the ${PLACEHOLDERS}
  .claude/
    .claude-plugin/plugin.json           plugin manifest
    settings.json                        permissions and hooks
    hooks/secret-scan.mjs                pre-write secret block
    hooks/format-gate.sh                 post-edit syntax gate
    hooks/house-voice.mjs                long em-dash and "+"-for-and block
    output-styles/house-voice.md         the house voice
    agents/engineering-reviewer.md       binding gate
    agents/security-reviewer.md          binding gate
    agents/deploy-gate.md                binding gate
    agents/design-critic.md              advisory
    skills/<name>/SKILL.md               29 skills
```

Claude Code then reads the skills, agents, output style, hooks, and settings automatically. Commit the tree to your repository like any other source. Fill the `CLAUDE.md` placeholders (listed in `AUDIT.md`) before your first deploy.

**Install every skill, and verify it.** A skill is discovered only from its installed location under `.claude/skills/<name>/SKILL.md`; one left flat or never copied is invisible to Claude and its standard goes unapplied. Do not cherry-pick a subset. After rehydrating, confirm the installed skill count equals the manifest (`START-HERE.md` prints this; there are currently 27), and note that the `SessionStart` hook `hooks/skills-check.sh` re-checks on every session and names any missing skills. A bundle that was uploaded but not fully installed is the common failure this guards against.
