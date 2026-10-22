import test from "node:test";
import assert from "node:assert/strict";
import { renderHtml } from "../src/report.ts";

const base = {
  at: "t", modelInfo: "m", items: [], passed: 0, rejected: 0, compare: [], topN: 5,
  sql: "SELECT a FROM x WHERE y = '<b>'", sqlMs: 12, rowCount: 36,
};

test("report shows the SQL (escaped), row count and model usage without secrets", () => {
  const html = renderHtml({ ...base, model: { name: "nemotron", route: "meterless", host: "127.0.0.1:8088", tokensIn: 10, tokensOut: 5, ms: 99, headers: {}, sentChars: 400, evidenceLines: 5 } });
  assert.ok(html.includes("SELECT a FROM x WHERE y = &#39;&lt;b&gt;&#39;"));
  assert.ok(html.includes("36 rows returned in 12 ms"));
  assert.ok(html.includes("local Nightshift endpoint"));
  assert.ok(html.includes("not reported by the endpoint"));
  assert.ok(!/authorization|bearer/i.test(html));
});

test("report states clearly when no model call was made", () => {
  assert.ok(renderHtml({ ...base, model: null }).includes("No model call was made"));
});

test("report shows a cost header when the endpoint returns one", () => {
  const html = renderHtml({ ...base, model: { name: "n", route: "meterless", host: "127.0.0.1:8088", ms: 1, headers: { "x-meterless-cost": "0.0004" }, sentChars: 1, evidenceLines: 1 } });
  assert.ok(html.includes("x-meterless-cost: 0.0004"));
});
