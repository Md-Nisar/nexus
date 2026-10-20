#!/usr/bin/env node
// SubagentStop — reports how many tokens the sub-agent that just stopped consumed.
// Also a CLI: `node .claude/hooks/agent-usage.mjs --report [subagentsDir]` prints one row per agent.
//
// Best-effort, never blocks (exit 0 always). Reads the agent's own transcript, de-duplicates
// streamed entries by message id, and sums the provider usage records. Honest limits:
//   * "last ctx" is the context size at the agent's last call. It is the number the UI shows
//     as "tokens"; it is NOT a total and NOT what is billed.
//   * Real volume is cache-read (re-sent context, billed at a reduced rate) plus cache-write
//     (billed at a premium) plus output. Uncached input is normally a few dozen tokens.
//   * output_tokens in transcripts is a lower bound (streamed snapshots), and thinking tokens
//     are not stored. Use the provider's usage page for billing.
//   * "input-equiv" weights cache-read/cache-write/output by NEXUS_USAGE_WEIGHTS ("0.1,1.25,5"
//     by default: an assumption, not a price list).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readStdin } from './_hooklib.mjs';

const LOG = path.join(os.homedir(), '.claude', 'nexus-agent-usage.jsonl');
// Committed ledger: one row per agent, attributed to a story and task, so the cost of the operating
// model can be studied across stories. Rows are cumulative per agent; a resumed agent adds a newer
// row and readers keep the last one.
const LEDGER = path.join(process.env.CLAUDE_PROJECT_DIR || process.cwd(), 'docs', 'metrics', 'agent-usage-ledger.csv');
const HEADER = 'date,story,task,agent_type,model,agent_id,calls,tool_uses,cache_read,cache_write,output_lower_bound,max_ctx,input_equiv';
const [wRead, wWrite, wOut] = (process.env.NEXUS_USAGE_WEIGHTS || '0.1,1.25,5')
  .split(',')
  .map(Number);

/** Sum usage over a transcript, one record per assistant message id (last write wins). */
export function summarize(file) {
  const byId = new Map();
  let prompts = 0;
  let toolUses = 0;
  let firstPrompt = '';
  const models = new Map();
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    let r;
    try {
      r = JSON.parse(line);
    } catch {
      continue;
    }
    const m = r.message;
    if (r.type === 'user' && typeof m?.content === 'string') {
      prompts += 1;
      if (!firstPrompt) firstPrompt = m.content;
    }
    if (r.type !== 'assistant' || !m) continue;
    if (Array.isArray(m.content)) toolUses += m.content.filter((b) => b.type === 'tool_use').length;
    if (m.usage && m.model !== '<synthetic>') {
      byId.set(m.id ?? r.uuid, m.usage);
      models.set(m.model, (models.get(m.model) ?? 0) + 1);
    }
  }
  const t = { calls: byId.size, toolUses, prompts, read: 0, write: 0, input: 0, out: 0, maxCtx: 0, lastCtx: 0 };
  for (const u of byId.values()) {
    const ctx = (u.input_tokens ?? 0) + (u.cache_read_input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0);
    t.read += u.cache_read_input_tokens ?? 0;
    t.write += u.cache_creation_input_tokens ?? 0;
    t.input += u.input_tokens ?? 0;
    t.out += u.output_tokens ?? 0;
    t.maxCtx = Math.max(t.maxCtx, ctx);
    t.lastCtx = ctx;
  }
  t.model = [...models.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';
  t.story = firstPrompt.match(/\bUS-\d{3,}\b/)?.[0] ?? '';
  t.task = firstPrompt.match(/\bT-\d{3}\b/)?.[0] ?? '';
  t.equiv = Math.round(t.input + t.read * wRead + t.write * wWrite + t.out * wOut);
  return t;
}

const k = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(2)}M` : n >= 1e3 ? `${Math.round(n / 1e3)}K` : `${n}`);

function line(label, t, prev) {
  const d = (key) => (prev ? t[key] - prev[key] : t[key]);
  const run = prev ? ` | this run: ${d('calls')} calls, read ${k(d('read'))}, write ${k(d('write'))}, ≈${k(t.equiv - prev.equiv)} input-equiv` : '';
  return (
    `${label}: ${t.calls} calls, ${t.toolUses} tool uses | last ctx ${k(t.lastCtx)} (UI figure), max ctx ${k(t.maxCtx)}` +
    ` | cache-read ${k(t.read)}, cache-write ${k(t.write)}, uncached in ${k(t.input)}, out ≥${k(t.out)}` +
    ` | ≈${k(t.equiv)} input-equiv${run}`
  );
}

function ledgerRow(id, type, t) {
  const date = new Date().toISOString().slice(0, 10);
  return [date, t.story, t.task, type ?? '', t.model, String(id).slice(0, 7), t.calls, t.toolUses, t.read, t.write, t.out, t.maxCtx, t.equiv].join(',');
}

function appendLedger(rows) {
  if (!rows.length) return;
  fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
  if (!fs.existsSync(LEDGER)) fs.writeFileSync(LEDGER, `${HEADER}\n`);
  fs.appendFileSync(LEDGER, `${rows.join('\n')}\n`);
}

/** Last row per agent_id wins (cumulative totals), then grouped by story and task. */
function ledgerSummary() {
  const last = new Map();
  for (const row of fs.readFileSync(LEDGER, 'utf8').trim().split('\n').slice(1)) {
    const c = row.split(',');
    last.set(c[5], c);
  }
  const groups = new Map();
  for (const c of last.values()) {
    const key = `${c[1] || '(none)'} ${c[2] || '(no task)'}`;
    const g = groups.get(key) ?? { agents: 0, read: 0, write: 0, equiv: 0 };
    g.agents += 1;
    g.read += Number(c[8]);
    g.write += Number(c[9]);
    g.equiv += Number(c[12]);
    groups.set(key, g);
  }
  for (const [key, g] of [...groups].sort()) {
    console.log(`${key}: ${g.agents} agents, cache-read ${k(g.read)}, cache-write ${k(g.write)}, ≈${k(g.equiv)} input-equiv`);
  }
}

function lastLogged(agentId) {
  try {
    const rows = fs.readFileSync(LOG, 'utf8').trim().split('\n').reverse();
    for (const row of rows) {
      const e = JSON.parse(row);
      if (e.agentId === agentId) return e.totals;
    }
  } catch {
    /* no log yet */
  }
  return undefined;
}

function findTranscript(input) {
  if (input.agent_transcript_path && fs.existsSync(input.agent_transcript_path)) return input.agent_transcript_path;
  const id = input.agent_id;
  if (id && input.transcript_path) {
    const sessionDir = input.transcript_path.replace(/\.jsonl$/, '');
    const p = path.join(sessionDir, 'subagents', `agent-${id}.jsonl`);
    if (fs.existsSync(p)) return p;
  }
  return undefined;
}

function report(dir) {
  const files = fs.readdirSync(dir).filter((f) => /^agent-.*\.jsonl$/.test(f));
  const rows = files.map((f) => {
    const id = f.replace(/^agent-|\.jsonl$/g, '');
    let type = '';
    try {
      type = JSON.parse(fs.readFileSync(path.join(dir, f.replace('.jsonl', '.meta.json')), 'utf8')).agentType ?? '';
    } catch {
      /* no meta */
    }
    return { id, type, t: summarize(path.join(dir, f)) };
  });
  rows.sort((a, b) => b.t.equiv - a.t.equiv);
  let total = 0;
  for (const r of rows) {
    total += r.t.equiv;
    console.log(line(`${r.type || 'agent'} ${r.id.slice(0, 7)}`, r.t));
  }
  console.log(`TOTAL ≈${k(total)} input-equiv across ${rows.length} agents (weights ${wRead}/${wWrite}/${wOut})`);
}

if (process.argv[2] === '--ledger') {
  ledgerSummary();
  process.exit(0);
}

if (process.argv[2] === '--backfill') {
  // Adds every agent in a subagents directory that the ledger does not know yet.
  const dir = process.argv[3];
  const known = fs.existsSync(LEDGER) ? new Set(fs.readFileSync(LEDGER, 'utf8').split('\n').map((r) => r.split(',')[5])) : new Set();
  const rows = [];
  for (const f of fs.readdirSync(dir).filter((n) => /^agent-.*\.jsonl$/.test(n))) {
    const id = f.replace(/^agent-|\.jsonl$/g, '');
    if (known.has(id.slice(0, 7))) continue;
    let type = '';
    try {
      type = JSON.parse(fs.readFileSync(path.join(dir, f.replace('.jsonl', '.meta.json')), 'utf8')).agentType ?? '';
    } catch {
      /* no meta */
    }
    rows.push(ledgerRow(id, type, summarize(path.join(dir, f))));
  }
  appendLedger(rows);
  console.log(`backfilled ${rows.length} agents`);
  process.exit(0);
}

if (process.argv[2] === '--report') {
  let dir = process.argv[3];
  if (!dir) {
    const root = path.join(os.homedir(), '.claude', 'projects');
    const cands = fs.readdirSync(root).flatMap((p) =>
      fs.readdirSync(path.join(root, p), { withFileTypes: true })
        .filter((e) => e.isDirectory() && fs.existsSync(path.join(root, p, e.name, 'subagents')))
        .map((e) => path.join(root, p, e.name, 'subagents')),
    );
    dir = cands.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
  }
  report(dir);
  process.exit(0);
}

try {
  const input = await readStdin();
  const file = findTranscript(input);
  if (file) {
    const totals = summarize(file);
    const id = input.agent_id ?? path.basename(file).replace(/^agent-|\.jsonl$/g, '');
    const msg = `Token usage — ${line(`${input.agent_type ?? 'agent'} ${String(id).slice(0, 7)}`, totals, lastLogged(id))}`;
    fs.mkdirSync(path.dirname(LOG), { recursive: true });
    fs.appendFileSync(LOG, `${JSON.stringify({ ts: new Date().toISOString(), agentId: id, agentType: input.agent_type, totals })}\n`);
    appendLedger([ledgerRow(id, input.agent_type, totals)]);
    process.stdout.write(`${JSON.stringify({ systemMessage: msg })}\n`);
    process.exit(0);
  }
} catch {
  /* reporting must never block an agent */
}
process.stdout.write('{}\n');
process.exit(0);
