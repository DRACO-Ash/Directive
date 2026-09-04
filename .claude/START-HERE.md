# START HERE: Bluestaq Foundations

This is the **Bluestaq Foundations** baseline: a portable set of native Claude Code artifacts (skills, reviewer agents, a house voice, a `CLAUDE.md` conventions template, and guardrail hooks) that you drop into any new code project so it inherits a robust, App Store ready engineering standard from the first commit.

It is distilled and merged from two real, deployed Bluestaq systems: a single-file, offline-capable static web artifact, and a server-backed container application with a Large Language Model (LLM) integration. Both ship to the internal **Bluestaq App Store** (`*.apps.bluestaq.com`). This baseline carries the standing machinery of both, so a project of either shape is covered without you choosing the wrong template.

## The governing bar

A newcomer with zero prior context can go from an empty repository to a deployed, App Store ready application using only this bundle, by reading one file and following one skill. Everything below either gets you there or proves it gets you there.

## What is inside (flat now, foldered after one command)

Every file sits at one level here, so nothing needs a folder upload to GitHub or Claude Code. The real path is encoded in the filename with `__` as the separator, for example `skills__security-hardening__SKILL.md` is really `skills/security-hardening/SKILL.md`. Run the rehydrate step once and you get the standard tree.

- `CLAUDE.md`: the always-true conventions a project inherits. Fill the `${PLACEHOLDERS}` on first adoption (the list is in `AUDIT.md`).
- `skills__*__SKILL.md`: 29 skills. A cold-start trio (`getting-started`, `environment-setup`, `glossary`), the planning and collaboration skills (`flight-plan`, `working-with-ai`, `resource-discipline`, `project-retrospective`, `learn-from-feedback`), one per engineering domain (including `ai-update-scan` for an in-app AI update or search feature), and the deploy cluster (`packaging`, `ci-cd`, `release-and-deploy`, `app-store-deployment`, `deploy-recipes`, `app-store-readiness`, `appstore-gate-compliance`).
- `agents__*.md`: four reviewers. Three binding gates (`engineering-reviewer`, `security-reviewer`, `deploy-gate`) that return `VERDICT: PASS` or `VERDICT: FAIL`, and one advisory `design-critic`.
- `output-styles__house-voice.md`: the Bluestaq house voice for every word a project emits.
- `settings.json`: pre-approved permissions, the App Store read-only tool allow-list, and the guardrail hooks (a pre-write secret scan that blocks a credential before it lands, a post-edit syntax gate, and a house-voice check that blocks a long em-dash or a "+" meaning "and" in authored content and commit messages).
- `hooks__secret-scan.mjs`, `hooks__format-gate.sh`, `hooks__house-voice.mjs`: the three guardrail scripts.
- `plugin.json`: the plugin manifest (rehydrates to `.claude-plugin/plugin.json`).
- `AUDIT.md`: the domain map, parameter table, provenance, and security findings.
- `COMPLETENESS.md`: the coverage proof.

## Install in two steps

### Step 1: rehydrate the flat files into a `.claude/` tree

Run one of these from inside this flat folder. Both expand the `__` separators into folders under `.claude/` at the root of your target repository, which is where Claude Code looks for skills, agents, the output style, hooks, and settings.

Bash (macOS, Linux, Windows Subsystem for Linux or Git Bash):

```bash
for f in *; do
  [ -f "$f" ] || continue
  case "$f" in START-HERE.md|REHYDRATE.md|AUDIT.md|COMPLETENESS.md) continue;; esac
  if [ "$f" = "plugin.json" ]; then t=".claude/.claude-plugin/plugin.json";
  else t=".claude/$(printf '%s' "$f" | sed 's#__#/#g')"; fi
  mkdir -p "$(dirname "$t")"
  cp "$f" "$t"
done
# CLAUDE.md belongs at the project root, not under .claude/
[ -f .claude/CLAUDE.md ] && mv .claude/CLAUDE.md ./CLAUDE.md
chmod +x .claude/hooks/*.sh .claude/hooks/*.mjs 2>/dev/null || true
# Verify EVERY skill in the manifest actually installed; a skill Claude cannot see is a standard it
# cannot apply. This catches a partial upload where some skills were never rehydrated.
man=$(grep -oE '"skills/[a-z0-9-]+"' .claude/.claude-plugin/plugin.json | sort -u | wc -l | tr -d ' ')
got=$(ls -d .claude/skills/*/SKILL.md 2>/dev/null | wc -l | tr -d ' ')
echo "Rehydrated into .claude/  and  CLAUDE.md at root"
echo "Skills installed: $got of $man from the manifest"
[ "$got" = "$man" ] || echo "WARNING: install is incomplete ($((man-got)) skill(s) missing). Install ALL skills before you start; the SessionStart hook names the missing ones each session."
```

PowerShell (Windows, native):

```powershell
Get-ChildItem -File | Where-Object { $_.Name -notin 'START-HERE.md','REHYDRATE.md','AUDIT.md','COMPLETENESS.md' } | ForEach-Object {
  if ($_.Name -eq 'plugin.json') { $t = '.claude\.claude-plugin\plugin.json' }
  else { $t = Join-Path '.claude' ($_.Name -replace '__','\') }
  New-Item -ItemType Directory -Force -Path (Split-Path $t) | Out-Null
  Copy-Item $_.FullName $t -Force
}
if (Test-Path .claude\CLAUDE.md) { Move-Item .claude\CLAUDE.md .\CLAUDE.md -Force }
$man = ([regex]::Matches((Get-Content .claude\.claude-plugin\plugin.json -Raw), '"skills/[a-z0-9-]+"') | ForEach-Object { $_.Value } | Sort-Object -Unique).Count
$got = (Get-ChildItem .claude\skills\*\SKILL.md -ErrorAction SilentlyContinue).Count
Write-Host "Rehydrated into .claude\  and  CLAUDE.md at root"
Write-Host "Skills installed: $got of $man from the manifest"
if ($got -ne $man) { Write-Host "WARNING: install is incomplete ($($man-$got) skill(s) missing). Install ALL skills before you start." }
```

After rehydration you have the standard layout: `.claude/skills/<name>/SKILL.md`, `.claude/agents/<name>.md`, `.claude/output-styles/house-voice.md`, `.claude/settings.json`, `.claude/hooks/*`, `.claude/.claude-plugin/plugin.json`, and `CLAUDE.md` at the repository root. Claude Code reads all of these automatically. The files commit to your repository like any other source.

**Install ALL skills, do not cherry-pick.** A skill is only discovered from its installed location, so a skill left flat (or never copied) is a standard Claude cannot see and will not apply. The rehydrate step installs every skill; the verification line above confirms the installed count matches the manifest, and a `SessionStart` hook (`hooks/skills-check.sh`) re-checks it on every session and names any that are missing. If you see that warning, the bundle was uploaded but not fully installed: re-run the rehydrate and commit the whole `.claude/skills/` tree.

### Step 2: adopt and start

1. Open `CLAUDE.md` and replace every `${PLACEHOLDER}` with your project's real value, then delete the one-line adoption note at the top. The placeholder list, with how to obtain each value, is in `AUDIT.md` and in the `environment-setup` and `security-hardening` skills.
2. Start a Claude Code session and say: **"Follow the getting-started skill."** It threads every other skill in the right order, from an empty repository to a deployed App Store app.

## Two paths, one baseline (read this once)

Every skill states which **archetype** it applies to, and your archetype changes which deploy template the App Store detects. Decide it before you build: **static or single-file** (offline HTML, dashboards, a built Single-Page Application served as static files) or **server-backed container** (an API, a backend, an LLM scan, a synced workspace, a database). The `getting-started` skill owns this decision as an executable first step (its "Step 0: decide your archetype"), with the full template list per archetype (`static-html`, `node-react`, `java-spring`, `python`, `docker-only`) and the strengths each inherits; read it there rather than duplicating the table here.

If you are unsure, the `getting-started` skill asks you the two questions that decide it.

## Skill levels: noob to expert

- **New to this:** read `getting-started`, then `glossary` whenever a word is unfamiliar. Every skill has a numbered Procedure and a Worked example you can copy.
- **Comfortable:** jump to the domain skill you need; each is self-contained with Decision rules and Failure modes.
- **Expert:** the Standards section of each skill is the checkable contract; the three gate agents enforce it. Read `AUDIT.md` and `COMPLETENESS.md` for the provenance and the coverage proof.

## House rules enforced throughout

A guide, not a leash. Held everywhere: never fabricated data, avoid the long em-dash (a single dash is fine), no `+` meaning "and" in prose. The Bluestaq default, which is your call on your own project: UK English, the `£`/`$`/`%` symbols, acronyms expanded on first use. Anything publish-facing or Bluestaq-brand-facing follows the brand in full. And nothing ships to the App Store without `deploy-gate` PASS plus an explicit human confirmation. The full voice is in `output-styles__house-voice.md`.
