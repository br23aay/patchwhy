// PatchWhy: "Which known-exploited vulnerabilities should we patch first, and why?"
//
//   npx tsx patchwhy.ts run [--no-model]          query Zetaris, rank, remember in H-MEM, explain, gate
//   npx tsx patchwhy.ts run --sample              same pipeline on a bundled snapshot: no Zetaris, no Nightshift, no keys
//   npx tsx patchwhy.ts snapshot                  save the live Zetaris rows to data/sample_rows.json (needs Zetaris)
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
const SAMPLE_FILE = path.join(here, "data", "sample_rows.json");
const TRACE: { t: string; step: string; detail: string }[] = [];
const trace = (step: string, detail: string) => TRACE.push({ t: new Date().toISOString(), step, detail });
const TOP_N = 5;
const MAX_MODEL_CALLS = 2; // iteration cap: at most 2 model calls per request

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
    const seen = new Set<string>();
    // Own tiny parser: handles CRLF, `export `, quotes and BOM. Never prints values.
    for (const raw of fs.readFileSync(f, "utf8").replace(/^\uFEFF/, "").split(/\r?\n/)) {
      const m = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!m || m[0].trim().startsWith("#")) continue;
      let v = m[2];
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (seen.has(m[1])) { if (v !== "") console.log(`WARNING: ${m[1]} appears more than once in .env; the FIRST value is used. Comment out the route you are not using.`); continue; }
      seen.add(m[1]);
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

function sampleRows(): any[][] {
  if (!fs.existsSync(SAMPLE_FILE)) throw new Error("data/sample_rows.json not found");
  const j = JSON.parse(fs.readFileSync(SAMPLE_FILE, "utf8"));
  if (!Array.isArray(j.rows)) throw new Error("data/sample_rows.json has no rows array");
  console.log(`  sample snapshot taken ${j.takenAt} from ${j.source}`);
  return j.rows;
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const sample = command === "run" && rest.includes("--sample");
  // Sample mode never reads .env, so it cannot reach for credentials or a model.
  if (!sample) loadEnv(); else console.log("SAMPLE MODE: bundled snapshot, no Zetaris, no Nightshift, no credentials read");
  const { HMEM, source } = await loadHMEM();
  const memDir = sample ? ".patchwhy-sample" : ".patchwhy";
  console.log(`engine source: ${source} | memory: ${memDir}/`);
  const hmem = new HMEM({ persistDir: path.join(here, memDir) });

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

  if (command === "snapshot") {
    console.log("querying Zetaris for a sample snapshot...");
    const rows = await zetarisRows();
    if (rows.length === 0) throw new Error("Zetaris returned 0 rows; not writing an empty snapshot (check the views in sql/zetaris.sql)");
    fs.mkdirSync(path.join(here, "data"), { recursive: true });
    fs.writeFileSync(SAMPLE_FILE, JSON.stringify({
      takenAt: new Date().toISOString(),
      source: "Zetaris vulnstore.assets+kev+epss (CISA KEV and FIRST EPSS public data, synthetic asset inventory)",
      columns: ["asset_id", "hostname", "environment", "internet_facing", "criticality", "cve", "epss", "ransomware", "due_date", "vendor", "product"],
      rows,
    }, null, 1));
    console.log(`wrote data/sample_rows.json (${rows.length} rows)`);
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
  const useModel = !rest.includes("--no-model") && !sample;
  trace("start", sample ? "sample mode" : "live mode");

  // 1. Data: one SQL statement across three sources, executed by Zetaris.
  console.log(sample ? "loading bundled sample snapshot (same columns as the Zetaris query)..." : "querying Zetaris (KEV + EPSS + assets)...");
  const sqlStart = Date.now();
  const rows = parseRows(sample ? sampleRows() : await zetarisRows());
  const sqlMs = Date.now() - sqlStart;
  console.log(`  ${rows.length} unpatched asset/vulnerability pairs`);

  trace("data", `${rows.length} rows from ${sample ? "sample snapshot" : "Zetaris"} in ${sqlMs} ms`);
  // Sample mode: seed one analyst decision on a fresh memory so the memory effect is visible.
  if (sample) {
    const probe = overrideText("A001", "CVE-2024-3400");
    const has = hmem.query(probe, { threshold: 0.3 }).memories.some((m: any) => String(m.memory.content).startsWith(probe));
    if (!has && rows.some((r) => r.assetId === "A001" && r.cve === "CVE-2024-3400")) {
      const rec = hmem.add({ content: `${probe} accepted risk. Reason: patch window agreed for Friday (sample seed)`, type: "general", source: "sample:seed" });
      console.log(`  sample seed: remembered ${rec.id} (accepted risk A001 CVE-2024-3400)`);
    }
  }
  // 2. Remembered analyst decisions (H-MEM) change the ranking.
  const { set: overrides, ids: overrideIds } = lookupOverrides(hmem, rows);

  // 3. Rank with fixed, auditable weights.
  const ranked = groupByAsset(rankRows(rows, overrides));
  const top = ranked.slice(0, TOP_N);
  trace("rank", `${overrides.size} H-MEM override(s) applied; top ${TOP_N} of ${ranked.length} assets`);

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
  let modelInfo = sample ? "model: not called (sample mode, fixed evidence-based templates)" : "model: skipped (--no-model)";
  let modelMeta: ReportData["model"] = null;
  if (useModel) {
    try {
      const block = top.map((f) => `[${memIdByRank.get(f.rank)}] ${evidenceText(f)}`).join("\n");
      // Guardrail: a hard cap on model calls per request (one retry on error), then stop.
      let r: Awaited<ReturnType<typeof nemotron>> | undefined, lastErr: unknown;
      for (let attempt = 1; attempt <= MAX_MODEL_CALLS && !r; attempt++) {
        try { r = await nemotron(block); } catch (e) { lastErr = e; console.log(`model attempt ${attempt}/${MAX_MODEL_CALLS} failed: ${(e as Error).message}`); }
      }
      if (!r) throw lastErr ?? new Error("model unavailable");
      modelLines = parseModelLines(r.text);
      modelMeta = { name: r.model, route: (process.env.MODEL_ROUTE === "meterless" && !/^(127\.0\.0\.1|localhost)(:|$)/.test(r.host)) ? "direct (MODEL_ROUTE says meterless but the endpoint is not local Nightshift)" : (process.env.MODEL_ROUTE || "direct"), host: r.host, tokensIn: r.tin, tokensOut: r.tout, ms: r.ms, headers: r.headers, sentChars: r.sentChars, evidenceLines: top.length };
      modelInfo = `model: ${r.model} | route: ${modelMeta?.route ?? "direct"} | tokens in/out: ${r.tin ?? "?"}/${r.tout ?? "?"} | ${r.ms} ms${r.recovered ? " | answer recovered from reasoning trace, gated below" : ""}`;
    } catch (err) {
      modelInfo = `model call failed (${(err as Error).message}); using templates`;
    }
  }

  // 6. Report.
  trace("explain", modelInfo);
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
  const modelFailed = useModel && !modelMeta;
  if (modelFailed || rejected > 0) {
    console.log(`NEEDS HUMAN REVIEW: ${modelFailed ? `the model was unavailable after ${MAX_MODEL_CALLS} attempts` : `${rejected} model explanation(s) failed the evidence gate`}. The ranking above is unaffected (it is computed in code); explanations shown are fixed templates. Check each with: npx tsx patchwhy.ts audit <memory id>`);
  }
  console.log("audit any evidence record:  npx tsx patchwhy.ts audit <memory id>");
  fs.mkdirSync(path.join(here, "out"), { recursive: true });
  const cmp = compareMethods(rows, ranked, TOP_N);
  fs.writeFileSync(path.join(here, "out", "report.html"), renderHtml({ at: stamp, modelInfo, items: htmlItems, passed, rejected, compare: cmp, topN: TOP_N, sql: SQL, sqlMs, rowCount: rows.length, model: modelMeta }));
  console.log("report written: out/report.html");
  trace("done", `${passed} passed, ${rejected} rejected`);
  fs.writeFileSync(path.join(here, "out", "trace.json"), JSON.stringify(TRACE, null, 1));
  console.log("trace written: out/trace.json");
  fs.writeFileSync(path.join(here, "out", "last_run.json"), JSON.stringify({ at: stamp, modelInfo, report }, null, 2));
}

function usage(): void {
  console.log(`PatchWhy
  npx tsx patchwhy.ts run [--no-model] [--sample]
  npx tsx patchwhy.ts snapshot
  npx tsx patchwhy.ts override <asset id> <CVE> "<reason>"
  npx tsx patchwhy.ts audit <memory id>\n  npx tsx patchwhy.ts compare`);
}

main().catch((err) => { console.error(err); process.exit(1); });
