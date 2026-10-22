// PatchWhy core: deterministic scoring, counterfactuals and the evidence gate.
// No network, no model. Everything here can be unit-tested and audited.

export interface Row {
  assetId: string;
  hostname: string;
  environment: string;
  internetFacing: string;
  criticality: number;
  cve: string;
  epss: number;
  ransomware: string;
  dueDate: string;
  vendor: string;
  product: string;
}

export interface Finding extends Row {
  score: number;
  overridden: boolean;
  rank: number;
  otherCves?: number;
  breadth?: number;
  acceptedCves?: string[];
}

// Column order must match the SELECT in patchwhy.ts.
export function parseRows(data: any[][]): Row[] {
  return data.map((d) => ({
    assetId: String(d[0]),
    hostname: String(d[1]),
    environment: String(d[2]),
    internetFacing: String(d[3]),
    criticality: Number(d[4]),
    cve: String(d[5]),
    epss: Number(d[6]),
    ransomware: String(d[7]),
    dueDate: String(d[8]),
    vendor: String(d[9]),
    product: String(d[10]),
  }));
}

// Fixed weights, chosen by me, never by the model. Maximum 110.
export function scoreRow(r: Row, exposureOverride?: string): number {
  const exposure = (exposureOverride ?? r.internetFacing) === "yes" ? 15 : 0;
  const env = r.environment === "production" ? 5 : r.environment === "staging" ? 0 : -5;
  const ransom = r.ransomware === "Known" ? 10 : 0;
  return round1(r.epss * 40 + r.criticality * 8 + exposure + ransom + env);
}

const round1 = (n: number) => Math.round(n * 10) / 10;

export const overrideKey = (assetId: string, cve: string) => `${assetId}|${cve}`;

export function rankRows(rows: Row[], overrides: Set<string>): Finding[] {
  const list = rows.map((r) => {
    const overridden = overrides.has(overrideKey(r.assetId, r.cve));
    const base = scoreRow(r);
    return { ...r, score: overridden ? round1(base * 0.5) : base, overridden, rank: 0 };
  });
  list.sort((a, b) => b.score - a.score || a.cve.localeCompare(b.cve) || a.assetId.localeCompare(b.assetId));
  list.forEach((f, i) => (f.rank = i + 1));
  return list;
}

// One finding per asset: its highest-scoring CVE, plus how many other KEV CVEs it carries.
export function groupByAsset(ranked: Finding[]): Finding[] {
  const byAsset = new Map<string, Finding[]>();
  for (const f of ranked) byAsset.set(f.assetId, [...(byAsset.get(f.assetId) ?? []), f]);
  const out: Finding[] = [];
  for (const list of byAsset.values()) {
    const best = [...list].sort((a, b) => b.score - a.score || b.epss - a.epss || a.cve.localeCompare(b.cve))[0];
    const other = list.length - 1;
    // Breadth bonus: 0.5 per other known-exploited CVE on the same asset, capped at 5.
    const breadth = Math.min(other, 10) * 0.5;
    out.push({
      ...best,
      score: round1(best.score + breadth),
      otherCves: other,
      breadth,
      acceptedCves: list.filter((x) => x.overridden).map((x) => x.cve),
    });
  }
  out.sort((a, b) => b.score - a.score || (b.otherCves ?? 0) - (a.otherCves ?? 0) || b.epss - a.epss || a.assetId.localeCompare(b.assetId));
  out.forEach((f, i) => (f.rank = i + 1));
  return out;
}

// "What would change this ranking?" computed by re-scoring, not by the model.
export function counterfactual(all: Finding[], f: Finding): string {
  if (f.internetFacing !== "yes") return "Already not internet-facing; exposure adds no points here.";
  const newScore = round1((f.overridden ? round1(scoreRow(f, "no") * 0.5) : scoreRow(f, "no")) + (f.breadth ?? 0));
  const others = all.filter((x) => !(x.assetId === f.assetId && x.cve === f.cve));
  const newRank = 1 + others.filter((x) => x.score > newScore).length;
  return `If ${f.hostname} were not internet-facing, its score would fall from ${f.score} to ${newScore} and its rank from ${f.rank} to ${newRank}.`;
}

export function daysOverdue(dueDate: string, today: Date): number {
  const d = Date.parse(dueDate);
  return Number.isNaN(d) ? 0 : Math.max(0, Math.floor((today.getTime() - d) / 86_400_000));
}

export function evidenceText(f: Finding): string {
  return (
    `F${f.rank} | asset ${f.assetId} ${f.hostname} (${f.environment}, internet-facing: ${f.internetFacing}, criticality ${f.criticality}) | ` +
    `${f.cve} in ${f.vendor} ${f.product}${f.otherCves ? ` (plus ${f.otherCves} other CISA KEV ${f.otherCves === 1 ? "CVE" : "CVEs"} on this asset)` : ""} | EPSS ${f.epss} | ransomware use: ${f.ransomware} | CISA KEV due ${f.dueDate} | ` +
    `priority score ${f.score}${f.breadth ? ` (includes breadth bonus ${f.breadth})` : ""}${f.acceptedCves?.length ? ` | analyst accepted risk on ${f.acceptedCves.join(", ")} (score halved for that CVE)` : ""}`
  );
}

export function templateExplanation(f: Finding, memId: string): string {
  return (
    `${f.hostname} (${f.assetId}) is exposed to ${f.cve}, which CISA lists as exploited, with EPSS ${f.epss} ` +
    `and ransomware use ${f.ransomware}; criticality ${f.criticality}, internet-facing ${f.internetFacing}, priority score ${f.score}${f.otherCves ? `, plus ${f.otherCves} other known-exploited ${f.otherCves === 1 ? "CVE" : "CVEs"} on the same asset` : ""} [${memId}].`
  );
}

export interface GateResult {
  ok: boolean;
  reasons: string[];
}

// Evidence gate: a model explanation passes only if it cites a memory id from THIS run
// and every number in it can be found in the cited evidence (or is a rank number 1..topN).
export function evidenceGate(text: string, evidenceById: Map<string, string>, topN: number): GateResult {
  const reasons: string[] = [];
  const cited = [...text.matchAll(/\[([A-Za-z0-9_-]+)\]/g)].map((m) => m[1]);
  if (cited.length === 0) reasons.push("no citation");
  for (const id of cited) if (!evidenceById.has(id)) reasons.push(`unknown citation ${id}`);
  const allowed = new Set<string>();
  for (const id of cited) {
    const ev = evidenceById.get(id);
    if (ev) for (const n of ev.match(/\d+(?:\.\d+)?/g) ?? []) allowed.add(n);
  }
  for (let i = 1; i <= topN; i++) allowed.add(String(i));
  const body = text.replace(/\[[A-Za-z0-9_-]+\]/g, " ");
  for (const n of body.match(/\d+(?:\.\d+)?/g) ?? []) {
    if (!allowed.has(n)) reasons.push(`number ${n} not in cited evidence`);
  }
  return { ok: reasons.length === 0, reasons };
}

// Parse "F1: ..." lines from the model reply.
export function parseModelLines(reply: string): Map<number, string> {
  const out = new Map<number, string>();
  for (const m of reply.matchAll(/^\s*F(\d+)\s*:\s*(.+)$/gm)) out.set(Number(m[1]), m[2].trim());
  return out;
}

// ---- Comparison with simpler rankings (shows what each method puts first; not a validation against real incidents) ----
export interface Summary {
  method: string;
  top: string[];
  distinctAssets: number;
  internetFacing: number;
  production: number;
  ransomware: number;
}

function summarise(method: string, rows: Row[], n: number): Summary {
  const top = rows.slice(0, n);
  return {
    method,
    top: top.map((r) => `${r.hostname} ${r.cve}`),
    distinctAssets: new Set(top.map((r) => r.assetId)).size,
    internetFacing: top.filter((r) => r.internetFacing === "yes").length,
    production: top.filter((r) => r.environment === "production").length,
    ransomware: top.filter((r) => r.ransomware === "Known").length,
  };
}

export function compareMethods(rows: Row[], patchwhy: Finding[], n: number): Summary[] {
  const byCrit = [...rows].sort((a, b) => b.criticality - a.criticality || a.assetId.localeCompare(b.assetId) || a.cve.localeCompare(b.cve));
  const byEpss = [...rows].sort((a, b) => b.epss - a.epss || a.assetId.localeCompare(b.assetId) || a.cve.localeCompare(b.cve));
  return [
    summarise("PatchWhy (one row per asset)", patchwhy, n),
    summarise("Asset criticality only", byCrit, n),
    summarise("EPSS only", byEpss, n),
  ];
}
