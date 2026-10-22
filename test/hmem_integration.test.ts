// Proves Meterless H-MEM is used in the working feature: a remembered analyst decision changes the ranking,
// and the same memory has an auditable ledger history. Runs against the real vendored engine.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadHMEM } from "../src/engine.ts";
import { lookupOverrides, overrideText } from "../src/overrides.ts";
import { parseRows, rankRows, groupByAsset } from "../src/patchwhy_core.ts";

const data = [
  ["A001", "fw-edge-01", "production", "yes", 5, "CVE-2024-3400", 0.99999, "Known", "2024-04-19", "Palo Alto Networks", "PAN-OS"],
  ["A001", "fw-edge-01", "production", "yes", 5, "CVE-2024-0012", 0.9, "Unknown", "2024-11-17", "Palo Alto Networks", "PAN-OS"],
  ["A012", "mail-01", "production", "yes", 5, "CVE-2021-34473", 0.99999, "Known", "2021-11-17", "Microsoft", "Exchange Server"],
];

test("a remembered analyst decision in H-MEM changes the ranking and is auditable", async () => {
  const { HMEM } = await loadHMEM();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "patchwhy-hmem-"));
  const hmem = new HMEM({ persistDir: dir });
  const rows = parseRows(data as any);

  const before = lookupOverrides(hmem, rows);
  assert.equal(before.set.size, 0);
  const firstBefore = groupByAsset(rankRows(rows, before.set))[0];
  assert.equal(firstBefore.assetId, "A001");

  const rec = hmem.add({ content: `${overrideText("A001", "CVE-2024-3400")} accepted risk. Reason: test`, type: "general", source: "analyst:test" });
  assert.ok(rec.id);

  const after = lookupOverrides(hmem, rows);
  assert.equal(after.set.size, 1);
  assert.equal(after.ids.get("A001|CVE-2024-3400"), rec.id);
  const g = groupByAsset(rankRows(rows, after.set));
  assert.equal(g.find((x) => x.assetId === "A001")!.cve, "CVE-2024-0012");
  assert.ok(g.find((x) => x.assetId === "A001")!.score < firstBefore.score);

  assert.ok(hmem.ledger.history(rec.id).length > 0, "ledger has history for the memory");
});
