// Run SQL statements against local Zetaris through the same REST endpoint PatchWhy uses.
//   npx tsx tools/zsql.ts "SELECT count(*) FROM vulnstore.kev"
//   npx tsx tools/zsql.ts --file sql/zetaris.sql      (runs each blank-line-separated statement in order)
// Reads the .env like patchwhy.ts. Never prints keys.
import fs from "node:fs";
import { randomUUID } from "node:crypto";

for (const f of [process.env.ENV_FILE, "/mnt/k/Hackathon/open-agent-hack/.env", "K:\\Hackathon\\open-agent-hack\\.env"].filter(Boolean) as string[]) {
  if (!fs.existsSync(f)) continue;
  for (const raw of fs.readFileSync(f, "utf8").replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const m = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m || m[0].trim().startsWith("#")) continue;
    let v = m[2]; if (/^(".*"|'.*')$/.test(v)) v = v.slice(1, -1);
    if (process.env[m[1]] === undefined && v !== "") process.env[m[1]] = v;
  }
  break;
}
const base = process.env.ZETARIS_REST_URL!, org = process.env.ZETARIS_ORG_ID!, key = process.env.ZETARIS_API_KEY!;
if (!base || !org || !key) { console.error("missing ZETARIS_* in .env"); process.exit(1); }

async function run(sql: string) {
  const res = await fetch(base.replace(/\/+$/, "") + "/sql-editor/sqls/run", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + key, "X-Org-ID": org, "X-Request-ID": randomUUID() },
    body: JSON.stringify({ queryId: randomUUID(), sql, source: "SqlEditor", limit: 500 }),
    signal: AbortSignal.timeout(180_000),
  });
  const text = await res.text();
  console.log(`> ${sql.slice(0, 110).replace(/\s+/g, " ")}${sql.length > 110 ? "..." : ""}`);
  console.log(`  HTTP ${res.status}: ${text.slice(0, 400)}`);
  return res.ok;
}

const args = process.argv.slice(2);
if (args[0] === "--file") {
  const stmts = fs.readFileSync(args[1], "utf8").split(/\r?\n\s*\r?\n/).map((s) => s.split(/\r?\n/).filter((l) => !l.trim().startsWith("--")).join(" ").trim()).filter(Boolean);
  for (const s of stmts) { if (!(await run(s))) { console.log("stopped at first failure"); break; } }
} else {
  await run(args.join(" "));
}
