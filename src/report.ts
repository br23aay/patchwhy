// Static HTML report for the demo. Pure function: data in, string out.
export interface ReportItem {
  rank: number; hostname: string; asset: string; cve: string; score: number; memory: string; gate: string;
  explanation: string; counterfactual: string; accepted: string[]; overdueDays: number; evidence: string;
}
export interface ReportData {
  at: string; modelInfo: string; items: ReportItem[]; passed: number; rejected: number;
  compare: { method: string; top: string[]; distinctAssets: number; internetFacing: number; production: number; ransomware: number }[];
  topN: number;
  sql: string; sqlMs: number; rowCount: number;
  model: null | { name: string; route: string; host: string; tokensIn?: number; tokensOut?: number; ms: number; headers: Record<string, string>; sentChars: number; evidenceLines: number };
}

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

function provenance(d: ReportData): string {
  const m = d.model;
  const local = m ? /^(127\.0\.0\.1|localhost|\[::1\])(:|$)/.test(m.host) : false;
  const hdrs = m ? Object.entries(m.headers) : [];
  const costHdr = hdrs.find(([k]) => /cost/i.test(k));
  const modelBlock = m
    ? `<ul>
      <li><b>Model:</b> ${esc(m.name)} via route <code>${esc(m.route)}</code> at <code>${esc(m.host)}</code> (${local ? (m.route === "meterless" ? "local Nightshift endpoint" : "local endpoint") : "remote endpoint"}).</li>
      <li><b>Usage:</b> ${esc(m.tokensIn ?? "?")} tokens in, ${esc(m.tokensOut ?? "?")} tokens out, ${esc(m.ms)} ms.</li>
      <li><b>Cost:</b> ${costHdr ? esc(costHdr[0] + ": " + costHdr[1]) : "not reported by the endpoint in this response. Nightshift's Proof tab holds the signed receipt for the call."}</li>
      ${hdrs.length ? `<li><b>Routing headers returned:</b> ${esc(hdrs.map(([k, v]) => k + "=" + v).join("; "))}</li>` : ""}
    </ul>`
    : "<p>No model call was made for this run (<code>--no-model</code>); explanations are templates.</p>";
  const privacy = `<ul>
      <li><b>Stays local:</b> the asset inventory and the Zetaris queries (Zetaris runs on this machine). The model never receives the raw inventory.</li>
      <li><b>Public inputs:</b> CISA KEV and FIRST EPSS are public data.</li>
      <li><b>Sent to the model:</b> ${m ? `${esc(m.evidenceLines)} evidence lines (${esc(m.sentChars)} characters) containing hostname, asset id, environment, exposure, criticality, CVE, EPSS, ransomware flag, KEV due date and score.` : "nothing"}</li>
      <li><b>Not sent:</b> API keys, tokens, the full inventory, or analyst reasons beyond the stated accepted-risk CVE.</li>
    </ul>`;
  return `<section class="card"><h2>How this answer was produced</h2>
    <h3>1. Data (Zetaris)</h3>
    <p class="muted">One statement, ${esc(d.rowCount)} rows returned in ${esc(d.sqlMs)} ms. KEV, EPSS and the asset view are joined inside Zetaris.</p>
    <pre>${esc(d.sql)}</pre>
    <h3>2. Model and cost</h3>${modelBlock}
    <h3>3. Privacy path</h3>${privacy}</section>`;
}

export function renderHtml(d: ReportData): string {
  const cards = d.items.map((i) => `
  <section class="card">
    <h2>#${i.rank} ${esc(i.hostname)} <small>${esc(i.asset)} &middot; ${esc(i.cve)}</small></h2>
    <p class="score">Priority score <b>${esc(i.score)}</b> <span class="gate ${i.gate === "PASS" ? "ok" : "warn"}">evidence gate: ${esc(i.gate)}</span></p>
    <p>${esc(i.explanation)}</p>
    <p class="muted">${esc(i.counterfactual)}</p>
    ${i.accepted.length ? `<p class="muted">Accepted risk on this asset: ${esc(i.accepted.join(", "))}</p>` : ""}
    <details><summary>Evidence ${esc(i.memory)}</summary><pre>${esc(i.evidence)}</pre>
    <p class="muted">KEV deadline passed ${esc(i.overdueDays)} days ago. Audit: <code>npx tsx patchwhy.ts audit ${esc(i.memory)}</code></p></details>
  </section>`).join("\n");
  const rows = d.compare.map((c) => `<tr><td>${esc(c.method)}</td><td>${esc(c.distinctAssets)}/${d.topN}</td><td>${esc(c.internetFacing)}/${d.topN}</td><td>${esc(c.production)}/${d.topN}</td><td>${esc(c.ransomware)}/${d.topN}</td><td class="muted">${esc(c.top.join("; "))}</td></tr>`).join("");
  return `<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PatchWhy report</title><style>
:root{--bg:#fff;--fg:#14171f;--muted:#5b6475;--card:#f4f6fa;--line:#d9dee8;--ok:#0a7a3d;--warn:#b45309}
@media (prefers-color-scheme:dark){:root{--bg:#10131a;--fg:#e8ecf4;--muted:#9aa4b8;--card:#181c26;--line:#2a3142;--ok:#4ade80;--warn:#fbbf24}}
body{background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;max-width:920px;margin:0 auto;padding:24px 16px}
*{box-sizing:border-box}body,.card,td{overflow-wrap:anywhere}.scroll{overflow-x:auto}h1{margin:0 0 4px}h3{margin:12px 0 4px;font-size:1rem}code{background:var(--bg);padding:0 4px;border-radius:4px}h2{margin:0 0 4px;font-size:1.15rem}small{color:var(--muted);font-weight:400}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.muted{color:var(--muted);font-size:.9rem}.gate{font-size:.85rem;margin-left:8px}.ok{color:var(--ok)}.warn{color:var(--warn)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);padding:8px;border-radius:6px}
table{width:100%;border-collapse:collapse;font-size:.9rem}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}th{white-space:nowrap;padding-right:14px}
@media (max-width:600px){td:last-child,th:last-child{display:none}}
</style></head><body>
<h1>PatchWhy</h1><p class="muted">Which known-exploited vulnerabilities should we patch first, and why? Sources: CISA KEV, FIRST EPSS and a synthetic asset inventory, joined in Zetaris. Generated ${esc(d.at)}.</p>
<p class="muted">${esc(d.modelInfo)} &middot; evidence gate: ${d.passed} passed, ${d.rejected} rejected.</p>
${cards}
${provenance(d)}
<h2>How other rankings compare (top ${d.topN})</h2>
<p class="muted">Shows what each method puts first. It is not a validation against real incidents, and PatchWhy's score uses some of these signals.</p>
<div class="scroll"><table><tr><th>Method</th><th>Distinct assets</th><th>Internet-facing</th><th>Production</th><th>Ransomware-linked</th><th>Top</th></tr>${rows}</table></div>
</body></html>`;
}
