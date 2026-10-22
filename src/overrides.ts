// Analyst decisions live in H-MEM. This is the ONLY place the ranking reads them back,
// so a test can prove the memory engine changes the answer.
import { overrideKey, type Row } from "./patchwhy_core.ts";

export function overrideText(assetId: string, cve: string): string {
  return `Analyst override: ${assetId} ${cve}`;
}

export function lookupOverrides(hmem: any, rows: Row[]): { set: Set<string>; ids: Map<string, string> } {
  const set = new Set<string>();
  const ids = new Map<string, string>();
  for (const r of rows) {
    const probe = overrideText(r.assetId, r.cve);
    const hit = hmem.query(probe, { threshold: 0.3 }).memories.find((m: any) => String(m.memory.content).startsWith(probe));
    if (hit) {
      set.add(overrideKey(r.assetId, r.cve));
      ids.set(overrideKey(r.assetId, r.cve), hit.memory.id);
    }
  }
  return { set, ids };
}
