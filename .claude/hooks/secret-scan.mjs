#!/usr/bin/env node
// secret-scan.mjs :: PreToolUse guardrail for Write|Edit|MultiEdit.
// Reads the hook payload on stdin, scans the content being written for credential
// patterns and for banned anti-patterns (client-side access gate; Dockerfile ENV PORT),
// and BLOCKS the write (exit code 2) if any match. Deterministic: same input, same verdict.
//
// Claude Code passes a JSON payload on stdin with tool_name and tool_input.
// Exit 0 = allow. Exit 2 = block; stderr is shown to the model as the reason.

import { readFileSync } from 'node:fs';

let raw = '';
try { raw = readFileSync(0, 'utf8'); } catch { process.exit(0); }

let payload = {};
try { payload = JSON.parse(raw || '{}'); } catch { process.exit(0); }

const ti = payload.tool_input || {};
// Collect every string that could carry new content across Write/Edit/MultiEdit.
const parts = [ti.content, ti.new_string, ti.file_text];
if (Array.isArray(ti.edits)) for (const e of ti.edits) parts.push(e && e.new_string);
const text = parts.filter(s => typeof s === 'string').join('\n');
if (!text) process.exit(0);

// Each rule is a labelled pattern, and the set below is the SAME set the packaging sweep
// in `scripts/build-package.sh` carries, in the same order and under the same flags, with
// one documented exception: `Dockerfile ENV PORT` is a build-contract check rather than a
// credential check and has no counterpart there. The two guard the same repository by
// different routes, so a difference between them is a hole in whichever is narrower, and
// that claim was false twice: the flags diverged, and then eight rules here folded case
// while their counterparts did not. `tests/test_secret_rule_parity.py` now asserts the set
// equality rather than trusting this comment, and it is the thing to keep green if you
// edit either file. Every rule carries `m`, and every rule but the prose one carries `i`;
// the prose rule must not fold case, because it matches anywhere in a line and folding
// turns every keyword argument ending in `_key` into a finding.
const RULES = [
  ['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/im],
  ['Generic API key assignment', /(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/im],
  ['Bearer token', /\bBearer\s+[A-Za-z0-9._\-]{20,}\b/im],
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/im],
  ['LLM provider key', /\b(?:sk-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,})\b/im],
  ['Google API key', /\bAIza[0-9A-Za-z_\-]{35}\b/im],
  ['Slack token', /\bxox[baprs]-[0-9A-Za-z\-]{10,}\b/im],
  ['GitLab personal token', /\bglpat-[0-9A-Za-z_\-]{20,}\b/im],
  ['Client-side access gate', /\b(?:ADMIN_)?PIN\s*=\s*['"][0-9A-Za-z]{4,}['"]/im],
  ['Unquoted environment-file credential', /^[ \t]*(?:(?:ENV|ARG|export|-e|--env|[-*\u25cf])[ \t]+)*['"`]?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|KEY|KEYS|PASSWORD|PASSWD|PWD)[A-Z0-9_]*=(?!\[REDACTED:)\S{8,}/im],
  ['Credential written into prose', /(?:^|[^A-Za-z0-9_])['"`]?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|KEY|KEYS|PASSWORD|PASSWD|PWD)[A-Z0-9_]*=(?!\[REDACTED:)(?!MISSING\()[^\s'"`]{8,}/m],
  ['Credential in a document table row', /^[ \t]*\|(?![^\n]*(?:\[REDACTED:|TBC))(?:[^|\n]*\|)*?[ \t]*`?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|KEY|KEYS|PASSWORD|PASSWD|PWD)[A-Z0-9_]*`?[ \t]*\|(?:[^|\n]*\|)*?[ \t]*`?[^ \t|]{8,}`?[ \t]*(?:\||$)/im],
  // The one rule with no counterpart in the packaging sweep: a build-contract check, not a
  // credential check. `ENV PORT` in a Dockerfile silently overrides the platform port 8080.
  ['Dockerfile ENV PORT', /^\s*ENV\s+PORT\s*=/im],
];

const hits = [];
for (const [label, re] of RULES) if (re.test(text)) hits.push(label);

if (hits.length) {
  console.error(
    'BLOCKED by bluestaq-foundations secret-scan hook. The content matches: ' +
    hits.join(', ') + '.\n' +
    'No secret may be written to source: use an environment variable or a runtime ' +
    'bring-your-own-key input, and render the value as [REDACTED:type] in any file. ' +
    'A client-side access gate (a hardcoded PIN) is banned; see skills/security-hardening. ' +
    'A Dockerfile "ENV PORT=" line is banned; the app must read process.env.PORT and ' +
    'default to 8080; see skills/release-and-deploy and skills/app-store-deployment.'
  );
  process.exit(2); // block
}
process.exit(0); // allow
