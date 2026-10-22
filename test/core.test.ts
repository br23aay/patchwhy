import test from "node:test";
import assert from "node:assert/strict";
import { compareMethods, groupByAsset, parseRows, rankRows, counterfactual, evidenceGate, parseModelLines, evidenceText, overrideKey } from "../src/patchwhy_core.ts";

// rows: asset, host, env, facing, crit, cve, epss, ransomware, due, vendor, product
const data = [
  ["A001", "fw-edge-01", "production", "yes", 5, "CVE-2024-3400", 0.99999, "Known", "2024-04-19", "Palo Alto Networks", "PAN-OS"],
  ["A008", "chat-01", "production", "no", 2, "CVE-2023-32315", 0.99999, "Unknown", "2023-09-14", "Ignite Realtime", "Openfire"],
  ["A016", "dev-sandbox-01", "development", "no", 1, "CVE-2021-44228", 0.99999, "Known", "2021-12-24", "Apache", "Log4j2"],
];

test("ranking is deterministic and sensible", () => {
  const r = rankRows(parseRows(data as any), new Set());
  assert.equal(r[0].assetId, "A001");
  assert.equal(r[2].assetId, "A016");
  assert.equal(r[0].score, 110);
});

test("override halves the score and is flagged", () => {
  const r = rankRows(parseRows(data as any), new Set([overrideKey("A001", "CVE-2024-3400")]));
  assert.equal(r.find((x) => x.assetId === "A001")!.overridden, true);
  assert.equal(r[0].assetId !== "A001", true);
});

test("counterfactual re-scores", () => {
  const r = rankRows(parseRows(data as any), new Set());
  assert.match(counterfactual(r, r[0]), /fall from 110 to 95 and its rank from 1 to 1/);
});

test("gate accepts grounded text and rejects invented numbers or citations", () => {
  const r = rankRows(parseRows(data as any), new Set());
  const ev = new Map([["mem-1", evidenceText(r[0])]]);
  assert.equal(evidenceGate("fw-edge-01 has EPSS 0.99999 and criticality 5 [mem-1].", ev, 3).ok, true);
  assert.equal(evidenceGate("fw-edge-01 has EPSS 0.5 [mem-1].", ev, 3).ok, false);
  assert.equal(evidenceGate("fw-edge-01 is bad.", ev, 3).ok, false);
  assert.equal(evidenceGate("fw-edge-01 is bad [mem-99].", ev, 3).ok, false);
});

test("model line parsing", () => {
  const m = parseModelLines("Intro\nF1: first reason [mem-1]\nF2: second [mem-2]");
  assert.equal(m.get(2), "second [mem-2]");
});

test("grouping gives one finding per asset with the extra CVE count", () => {
  const more = [...data, ["A001", "fw-edge-01", "production", "yes", 5, "CVE-2024-0012", 0.9, "Unknown", "2024-11-17", "Palo Alto Networks", "PAN-OS"]];
  const g = groupByAsset(rankRows(parseRows(more as any), new Set()));
  assert.equal(g.length, 3);
  assert.equal(g[0].assetId, "A001");
  assert.equal(g[0].otherCves, 1);
  assert.equal(g[0].cve, "CVE-2024-3400");
  assert.equal(g[0].score, 110.5);
});

test("accepted CVEs are listed on the grouped asset", () => {
  const more = [...data, ["A001", "fw-edge-01", "production", "yes", 5, "CVE-2024-0012", 0.9, "Unknown", "2024-11-17", "Palo Alto Networks", "PAN-OS"]];
  const g = groupByAsset(rankRows(parseRows(more as any), new Set([overrideKey("A001", "CVE-2024-3400")])));
  const a = g.find((x) => x.assetId === "A001")!;
  assert.deepEqual(a.acceptedCves, ["CVE-2024-3400"]);
  assert.equal(a.cve, "CVE-2024-0012");
});

test("comparison summarises three methods", () => {
  const rows = parseRows(data as any);
  const s = compareMethods(rows, groupByAsset(rankRows(rows, new Set())), 2);
  assert.equal(s.length, 3);
  assert.equal(s[0].distinctAssets, 2);
});
