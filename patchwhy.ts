// PatchWhy: "Which known-exploited vulnerabilities should we patch first, and why?"
//
//   npx tsx patchwhy.ts run [--no-model]          query Zetaris, rank, remember in H-MEM, explain, gate
//   npx tsx patchwhy.ts override A001 CVE-2024-3400 "accepted risk until Friday window"
//   npx tsx patchwhy.ts audit mem-3               full ledger history of one memory
//
// Sources joined in Zetaris: CISA KEV + FIRST EPSS (public) + assets (synthetic inventory).
// Memory: Meterless H-MEM (every record has a source; append-only ledger).
// Model: NVIDIA Nemotron through Meterless Nightshift. It only writes explanations;
// scoring and counterfactuals are plain code, and an evidence gate checks the model's text.

import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadHMEM } from "./src/engine.ts";
import {
  parseRows, rankRows, groupByAsset, counterfactual, daysOverdue, evidenceText, templateExplanation,
  evidenceGate, parseModelLines, overrideKey, compareMethods, type Finding,
} from "./src/patchwhy_core.ts";
import { lookupOverrides, overrideText } from "./src/overrides.ts";
import { renderHtml, type ReportItem, type ReportData } from "./src/report.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const TOP_N = 5;

const SQL = `SELECT a.asset_id, a.hostname, a.environment, a.internet_facing, a.criticality, k.cve, e.epss, k.ransomware, k.due_date, k.vendor, k.product
FROM vulnstore.assets a
JOIN vulnstore.kev k ON a.vendor = k.vendor AND a.product = k.product
JOIN vulnstore.epss e ON k.cve = e.cve
WHERE a.patch_status = 'unpatched'`.replace(/\s+/g, " ");

function loadEnv(): void {
  const candidates = [
    process.env.ENV_FILE,
    path.join(here, ".env"),
    path.join(here, "..", ".env"),
    path.join(here, "..", "..", "open-agent-hack", ".env"),
    "/mnt/k/Hackathon/open-agent-hack/.env",
    "K:\\Hackathon\\open-agent-hack\\.env",
  ].filter(Boolean) as string[];
  for (const f of candidates) {
    if (!fs.existsSync(f)) continue;
    // Own tiny parser: handles CRLF, `export `, quotes and BOM. Never prints values.
    for (const raw of fs.readFileSync(f, "utf8").replace(/^\uFEFF/, "").split(/\r?\n/)) {
      const m = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!m || m[0].trim().startsWith("#")) continue;
      let v = m[2];
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (process.env[m[1]] === undefined && v !== "") process.env[m[1]] = v;
    }
    console.log(`env file: ${f}`);
    return;
  }
  console.log("env file: none found (tried " + candidates.length + " locations)");
}

async function zetarisRows(): Promise<any[][]> {
  const base = process.env.ZETARIS_REST_URL, org = process.env.ZETARIS_ORG_ID, key = process.env.ZETARIS_API_KEY;
  const missing = [["ZETARIS_REST_URL", base], ["ZETARIS_ORG_ID", org], ["ZETARIS_API_KEY", key]].filter(([, v]) => !v).map(([n]) => n);
  if (missing.length) throw new Error("missing or empty in .env: " + missing.join(", "));
  const res = await fetch(base.replace(/\/+$/, "") + "/sql-editor/sqls/run", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer " + key,
      "X-Org-ID": org,
      "X-Request-ID": randomUUID(),
    },
    body: JSON.stringify({ queryId: randomUUID(), sql: SQL, source: "SqlEditor", limit: 500 }),
    signal: AbortSignal.timeout(180_000),
  });
  if (!res.ok) throw new Error(`Zetaris returned ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const json: any = await res.json();
  if (!Array.isArray(json.data)) throw new Error("unexpected Zetaris reply: " + JSON.stringify(json).slice(0, 200));
  return json.data;
}

async function nemotron(evidenceBlock: string): Promise<{ text: string; model: string; ms: number; tin?: number; tout?: number; recovered?: boolean; headers: Record<string, string>; host: string; sentChars: number }> {
  const base = process.env.MODEL_BASE_URL, key = process.env.MODEL_API_KEY;
  if (!base || !key) throw new Error("MODEL_BASE_URL / MODEL_API_KEY not set");
  const model = process.env.NEMOTRON_MODEL || "meterless/auto";
  const headers: Record<string, string> = { "content-type": "application/json", authorization: `Bearer ${key}` };
  if ((process.env.MODEL_ROUTE || "").toLowerCase() === "meterless") {
    headers["meterless-app"] = "patchwhy";
    headers["meterless-scope"] = "user";
  }
  const t0 = Date.now();
  const body: any = {
    model, temperature: 0.2, max_tokens: 6000,
    messages: [
      {
        role: "system",
        content:
          "/no_think\nYou explain a vulnerability patch ranking to a security manager. Use ONLY the evidence lines given. " +
          "Write exactly one line per finding in the form `F<n>: <one or two sentences> [<memory id>]`, citing that finding's memory id in square brackets. " +
          "Do not use any number that is not in that finding's evidence. Do not add findings or advice about other items. Keep the hostname and CVE in each line, and mention any count of other known-exploited CVEs and any accepted-risk CVE that the evidence states. Answer directly without showing your reasoning.",
      },
      { role: "user", content: evidenceBlock },
    ],
  };
  const call = (extra: boolean) =>
    fetch(base.replace(/\/+$/, "") + "/chat/completions", {
      method: "POST",
      headers,
      signal: AbortSignal.timeout(180_000),
      body: JSON.stringify(extra ? { ...body, chat_template_kwargs: { enable_thinking: false } } : body),
    });
  // Ask the model not to think; if the endpoint rejects the extra field, retry without it.
  let res = await call(true);
  if (res.status === 400 || res.status === 422) res = await call(false);
  if (!res.ok) throw new Error(`model endpoint returned ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const j: any = await res.json();
  const msg = j?.choices?.[0]?.message ?? {};
  let text = String(msg.content ?? "").replace(/<think>[\s\S]*?<\/think>/g, "").trim();
  let recovered = false;
  if (!text && msg.reasoning_content) {
    // Reasoning models sometimes put the final lines only in the trace. Take the LAST "F<n>:" lines;
    // the evidence gate checks them exactly like any other model text.
    const last = new Map<number, string>();
    for (const m of String(msg.reasoning_content).matchAll(/^\s*F(\d+)\s*:\s*(.+)$/gm)) last.set(Number(m[1]), m[2].trim());
    text = [...last.entries()].map(([n, t]) => `F${n}: ${t}`).join("\n");
    recovered = text.length > 0;
  }
  if (!text) {
    throw new Error(`empty model reply (finish_reason ${j?.choices?.[0]?.finish_reason}; fields: ${Object.keys(msg).join(",")}; completion tokens ${j?.usage?.completion_tokens})`);
  }
  // Keep only response headers that describe routing, cost or receipts. Never request headers (they hold the key).
  const headersOut: Record<string, string> = {};
  res.headers.forEach((v, k) => { if (/meterless|receipt|cost|route|privacy|provider/i.test(k)) headersOut[k] = v; });
  let host = "unknown";
  try { host = new URL(base).host; } catch { /* keep unknown */ }
  return {
    text, model: j.model ?? model, ms: Date.now() - t0, tin: j.usage?.prompt_tokens, tout: j.usage?.completion_tokens,
    recovered, headers: headersOut, host, sentChars: evidenceBlock.length,
  };
}

async function main(): Promise<void> {
  loadEnv();
  const [command, ...rest] = process.argv.slice(2);
  const { HMEM, source } = await loadHMEM();
  console.log(`engine source: ${source} | memory: .patchwhy/`);
  const hmem = new HMEM({ persistDir: path.join(here, ".patchwhy") });

  if (command === "override") {
    const [assetId, cve, ...why] = rest.filter((a) => !a.startsWith("--"));
    if (!assetId || !cve || why.length === 0) return usage();
    const rec = hmem.add({
      content: `${overrideText(assetId, cve)} accepted risk. Reason: ${why.join(" ")}`,
      type: "general",
      source: "analyst:cli",
    });
    console.log(`remembered ${rec.id} [${rec.layer}] ${rec.content}`);
    return;
  }

  if (command === "audit") {
    const id = rest[0];
    if (!id) return usage();
    const history = hmem.ledger.history(id);
    if (history.length === 0) console.log(`no ledger entries for ${id}`);
    for (const e of history) console.log(`- ${e.action} by ${e.actor} at ${new Date(e.timestamp).toISOString()}`);
    return;
  }

  if (command === "compare") {
    console.log("querying Zetaris (KEV + EPSS + assets)...");
    const rows = parseRows(await zetarisRows());
    const grouped = groupByAsset(rankRows(rows, new Set()));
    console.log(`\nTop ${TOP_N} under three methods (${rows.length} asset/vulnerability pairs). This shows what each method puts first; it is not a validation against real incidents.\n`);
    for (const s of compareMethods(rows, grouped, TOP_N)) {
      console.log(s.method);
      console.log(`  top: ${s.top.join("; ")}`);
      console.log(`  distinct assets ${s.distinctAssets}/${TOP_N} | internet-facing ${s.internetFacing}/${TOP_N} | production ${s.production}/${TOP_N} | ransomware-linked ${s.ransomware}/${TOP_N}\n`);
    }
    return;
  }

  if (command !== "run") return usage();
  const useModel = !rest.includes("--no-model");

  // 1. Data: one SQL statement across three sources, executed by Zetaris.
  console.log("querying Zetaris (KEV + EPSS + assets)...");
  const sqlStart = Date.now();
  const rows = parseRows(await zetarisRows());
  const sqlMs = Date.now() - sqlStart;
  console.log(`  ${rows.length} unpatched asset/vulnerability pairs`);

  // 2. Remembered analyst decisions (H-MEM) change the ranking.
  const { set: overrides, ids: overrideIds } = lookupOverrides(hmem, rows);

  // 3. Rank with fixed, auditable weights.
  const ranked = groupByAsset(rankRows(rows, overrides));
  const top = ranked.slice(0, TOP_N);

  // 4. Remember each top finding with its source (H-MEM requires a source).
  const stamp = new Date().toISOString();
  const memIdByRank = new Map<number, string>();
  const evidenceById = new Map<string, string>();
  for (const f of top) {
    const content = evidenceText(f);
    const existing = hmem.query(content, { threshold: 0.5 }).memories.find((m: any) => m.memory.content === content);
    const id = existing
      ? existing.memory.id
      : hmem.add({ content, type: "general", source: `zetaris:vulnstore.assets+kev+epss@${stamp}` }).id;
    memIdByRank.set(f.rank, id);
    evidenceById.set(id, content);
  }

  // 5. Explanations: Nemotron writes them, the evidence gate checks them.
  let modelLines = new Map<number, string>();
  let modelInfo = "model: skipped (--no-model)";
  let modelMeta: ReportData["model"] = null;
  if (useModel) {
    try {
      const block = top.map((f) => `[${memIdByRank.get(f.rank)}] ${evidenceText(f)}`).join("\n");
      const r = await nemotron(block);
      modelLines = parseModelLines(r.text);
      modelMeta = { name: r.model, route: process.env.MODEL_ROUTE || "direct", host: r.host, tokensIn: r.tin, tokensOut: r.tout, ms: r.ms, headers: r.headers, sentChars: r.sentChars, evidenceLines: top.length };
      modelInfo = `model: ${r.model} | route: ${process.env.MODEL_ROUTE || "direct"} | tokens in/out: ${r.tin ?? "?"}/${r.tout ?? "?"} | ${r.ms} ms${r.recovered ? " | answer recovered from reasoning trace, gated below" : ""}`;
    } catch (err) {
      modelInfo = `model call failed (${(err as Error).message}); using templates`;
    }
  }

  // 6. Report.
  console.log("\n" + modelInfo + "\n");
  const today = new Date();
  const report: any[] = [];
  const htmlItems: ReportItem[] = [];
  let passed = 0, rejected = 0;
  for (const f of top) {
    const id = memIdByRank.get(f.rank)!;
    let text = modelLines.get(f.rank);
    let gate = "template";
    if (text) {
      const g = evidenceGate(text, evidenceById, TOP_N);
      if (g.ok) { gate = "PASS"; passed++; }
      else { gate = "REJECTED (" + g.reasons.join("; ") + ")"; rejected++; text = undefined; }
    }
    const explanation = text ?? templateExplanation(f, id);
    const od = daysOverdue(f.dueDate, today);
    const ov = overrideIds.get(overrideKey(f.assetId, f.cve));
    console.log(`#${f.rank}  ${f.hostname} (${f.assetId})  ${f.cve}  score ${f.score}${f.overridden ? `  [accepted risk, see ${ov}]` : ""}`);
    console.log(`    ${explanation}`);
    console.log(`    why-not-lower: ${counterfactual(ranked, f)}`);
    if (f.acceptedCves?.length) {
      console.log(`    accepted risk on this asset: ${f.acceptedCves.map((c) => `${c} (${overrideIds.get(overrideKey(f.assetId, c)) ?? "?"})`).join(", ")}`);
    }
    console.log(`    evidence ${id} | KEV deadline passed ${od} days ago | evidence gate: ${gate}\n`);
    htmlItems.push({ rank: f.rank, hostname: f.hostname, asset: f.assetId, cve: f.cve, score: f.score, memory: id, gate: gate.startsWith("REJECTED") ? "REJECTED, template used" : gate, explanation, counterfactual: counterfactual(ranked, f), accepted: (f.acceptedCves ?? []).map((c) => `${c} (${overrideIds.get(overrideKey(f.assetId, c)) ?? "?"})`), overdueDays: od, evidence: evidenceById.get(id)! });
    report.push({ rank: f.rank, asset: f.assetId, cve: f.cve, score: f.score, memory: id, gate, explanation });
  }
  console.log(`gate summary: ${passed} model explanations passed, ${rejected} rejected, rest used templates`);
  console.log("audit any evidence record:  npx tsx patchwhy.ts audit <memory id>");
  fs.mkdirSync(path.join(here, "out"), { recursive: true });
  const cmp = compareMethods(rows, groupByAsset(rankRows(rows, new Set())), TOP_N);
  fs.writeFileSync(path.join(here, "out", "report.html"), renderHtml({ at: stamp, modelInfo, items: htmlItems, passed, rejected, compare: cmp, topN: TOP_N, sql: SQL, sqlMs, rowCount: rows.length, model: modelMeta }));
  console.log("report written: out/report.html");
  fs.writeFileSync(path.join(here, "out", "last_run.json"), JSON.stringify({ at: stamp, modelInfo, report }, null, 2));
}

function usage(): void {
  console.log(`PatchWhy
  npx tsx patchwhy.ts run [--no-model]
  npx tsx patchwhy.ts override <asset id> <CVE> "<reason>"
  npx tsx patchwhy.ts audit <memory id>\n  npx tsx patchwhy.ts compare`);
}

main().catch((err) => { console.error(err); process.exit(1); });
