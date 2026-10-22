# Agent Loop Spec: "Why was this vulnerability ranked first?"

Team Bharadwaj | Open Agent Hackathon 2026 | Track 02

## Business question (two sources)
"Which known-exploited vulnerabilities should a UK mid-size company patch first this week, and why?"

| Source | What it holds | Access |
|---|---|---|
| CISA KEV catalogue | CVEs confirmed exploited in the wild, vendor/product, date added, due date, ransomware use | public JSON (GitHub mirror) |
| FIRST EPSS | Probability (0-1) that a CVE is exploited in the next 30 days, plus percentile | public REST API |

Both are registered in Zetaris as Lightning REST tables and joined on CVE id.

## Agent loop (design notes; the implementation is in patchwhy.ts)
1. **Plan**: Nemotron (via Meterless Nightshift, `meterless/auto`) turns the question into a SQL plan.
2. **Query**: the agent runs one SQL statement against Zetaris joining KEV and EPSS.
3. **Score**: rank by EPSS, ransomware flag and KEV due date. The weights are fixed in code, not chosen by the model.
4. **Remember**: each ranked finding is written to H-MEM with its source (record id, CVE, source URL).
5. **Explain**: the model answers only from retrieved memories and cites ids, for example [mem-3].
6. **Audit**: `audit <id>` shows the append-only ledger entry. Nightshift signed receipts prove which model ran.
7. **Sleep cycle**: consolidates repeated findings between runs.

## Inputs / outputs
- Input: a natural-language question.
- Output: ranked list, one-paragraph rationale per item, provenance ids, receipt reference.

## Guardrails
- A memory without a source is rejected (H-MEM rule).
- If retrieval returns nothing, the agent says so instead of guessing.
- No secrets in the repo; `.env` is git-ignored.

## Demo (target 3 minutes)
Ask question, show the SQL, show the ranking, ask "why is CVE-X first?", show the cited memory, run `audit`, show the Nightshift receipt.

## Sponsor tech
Zetaris (data), Cursor (build), Meterless H-MEM + Nightshift (memory and routing), NVIDIA Nemotron (reasoning).

## Declared pre-existing code
agent-starter template (Meterless) and H-MEM reference; the `llm.ts` Nemotron path and the Zetaris scenario are new work.

## Open risks
- Credits for Cursor and Meterless unconfirmed.
- Zetaris REST tables and join verified 21 Oct (see zetaris-kev-epss.sql).
