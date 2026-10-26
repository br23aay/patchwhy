# PatchWhy

**Which known-exploited vulnerabilities should we patch first, and why?**

PatchWhy is an agent for small security teams. It joins three data sources in Zetaris, ranks the unpatched assets with fixed, auditable weights, remembers analyst decisions in Meterless H-MEM, and has NVIDIA Nemotron explain each ranking. Every explanation must pass an evidence gate before it is shown. Entry for **Track 02: The Agent That Can Explain Why**.

> **Track:** The Agent That Can Explain Why
> **Sponsor technology:** Zetaris, Meterless (H-MEM and Nightshift), NVIDIA Nemotron
> **Run without any credentials:** `npm install && npm run setup && npx tsx patchwhy.ts run --sample`

## The problem
Security teams cannot patch everything. Ranking by a generic severity score sends them after the wrong things, and a ranking nobody can explain is hard to defend. PatchWhy puts real exploitation evidence together with what the company actually runs, and shows its reasoning.

## What it does
1. **Data (Zetaris).** One SQL statement joins three sources, queried in place:
   - CISA Known Exploited Vulnerabilities (public JSON)
   - FIRST EPSS exploitation probabilities (public API)
   - an asset inventory (**synthetic**: a made-up company, see `data/assets.csv`)
2. **Score (plain code).** Fixed weights: EPSS, asset criticality, internet exposure, ransomware use, environment, and a small bonus for other known-exploited CVEs on the same asset. The model never chooses the ranking.
3. **Remember (Meterless H-MEM).** Each top finding is stored with its source. Analyst decisions ("accepted risk on this CVE") are stored in H-MEM and change the next ranking. Every record has an append-only ledger you can audit.
4. **Explain (NVIDIA Nemotron via Meterless Nightshift).** The model writes one line per finding from the evidence only.
5. **Evidence gate.** A model line is shown only if it cites a memory id from this run and every number in it appears in the cited evidence. Otherwise a template sentence is used and the rejection is reported.
6. **Counterfactuals.** "If this host were not internet-facing, its score would fall from X to Y and its rank from A to B." Computed by re-scoring, not by the model.
7. **Guardrails.** At most 2 model calls per request. If the model is unavailable, or the gate rejects a line, the run prints `NEEDS HUMAN REVIEW`, shows template sentences instead, and points to the `audit` command. The ranking itself never depends on the model.
8. **Report.** `out/report.html` shows the findings, evidence, gate results, a comparison with simpler rankings, and a "How this answer was produced" section: the exact SQL, rows and time, the model, route and endpoint, token usage, and what is and is not sent to the model.

### Architecture
```mermaid
flowchart LR
  KEV[CISA KEV<br/>REST] --> Z
  EPSS[FIRST EPSS<br/>REST] --> Z
  INV[Asset inventory<br/>synthetic] --> Z
  Z[Zetaris USL<br/>one SQL join] --> S[Scoring in code<br/>fixed weights]
  M[(Meterless H-MEM<br/>decisions + evidence)] <--> S
  S --> E[Evidence records<br/>with memory ids]
  E --> N[NVIDIA Nemotron<br/>via Nightshift]
  N --> G{Evidence gate}
  G -- pass --> R[Report + counterfactuals]
  G -- reject / model down --> T[Template text<br/>NEEDS HUMAN REVIEW]
  T --> R
```
The model sits after the ranking. It can change the wording of an explanation, never the order.

| Component | Role |
|---|---|
| Zetaris | One SQL join across three sources (the USL), see [docs/ZETARIS_USL.md](docs/ZETARIS_USL.md) |
| Meterless H-MEM | Remembers evidence and analyst decisions with sources; decisions change the next ranking |
| Meterless Nightshift + NVIDIA Nemotron | Writes one explanation per finding from the evidence only |
| Plain TypeScript | Scoring, counterfactuals, evidence gate, report |

### Failure handling
| Failure | Behaviour |
|---|---|
| Model unavailable | One retry (at most 2 model calls), then template text and `NEEDS HUMAN REVIEW` |
| Model line fails the evidence gate | That line is replaced by a template and the rejection is reported |
| Zetaris unreachable or empty | `run` stops with the error; `snapshot` refuses to write an empty file; `run --sample` still works |
| Model returns reasoning text only | The last `F<n>:` lines are taken and still pass the same gate |

### Data and licensing
CISA KEV and FIRST EPSS are public data. The asset inventory (`data/assets.csv`) is synthetic: a made-up company, not real systems. `data/sample_rows.json` is a snapshot of the Zetaris join output on 26 Oct 2026. No real customer data is used.

![PatchWhy report from a real run: ranked findings, evidence, SQL, model route and privacy path](docs/report.png)

## Try it without any credentials (sample mode)
```bash
npm install
npm run setup
npx tsx patchwhy.ts run --sample
```
Sample mode needs no Zetaris, no Nightshift and no keys, and never reads `.env`. It runs the same pipeline (scoring, grouping, H-MEM memory, counterfactuals, evidence records) on `data/sample_rows.json`, a snapshot of the real Zetaris join output (CISA KEV and FIRST EPSS public data with the synthetic inventory). The model is not called, so explanations use the fixed evidence-based templates. It seeds one analyst decision in a separate memory folder (`.patchwhy-sample/`) so the memory effect is visible. Output: `out/report.html` and a step trace in `out/trace.json`. The live run with Nemotron is the one shown in the demo video.

## Sample inputs and outputs
All three run offline in sample mode (`--sample`, no keys). Output below is from the bundled snapshot; the model is not called, so explanations are the fixed templates.

**1. Input:** `npx tsx patchwhy.ts run --sample`
```
#1  mail-01 (A012)       CVE-2021-34473  score 115
    why-not-lower: If mail-01 were not internet-facing, its score would fall from 115 to 100 and its rank from 1 to 5.
#2  fw-edge-01 (A001)    CVE-2024-0012   score 112.4   [accepted risk on this asset: CVE-2024-3400 (mem-1)]
#3  vpn-gw-01 (A003)     CVE-2024-21887  score 110.5
#4  app-orders-01 (A014) CVE-2021-44228  score 110.5
#5  wiki-01 (A005)       CVE-2023-22518  score 103
```

**2. Input:** record an analyst decision, then run again
`npx tsx patchwhy.ts override A012 CVE-2021-34473 "accepted risk until the Friday window" --sample`
```
remembered mem-7 [working] Analyst override: A012 CVE-2021-34473 accepted risk. Reason: accepted risk until the Friday window
#1  mail-01 (A012)  CVE-2021-26855  score 115     <- the headline CVE on mail-01 changed
    accepted risk on this asset: CVE-2021-34473 (mem-7)
```
The remembered decision changed the next ranking: the accepted CVE is no longer the headline and is listed as accepted risk with its memory id.

**3. Input:** `npx tsx patchwhy.ts audit mem-1 --sample`
```
- create by system at <timestamp>
- read by system at <timestamp>
- read by system at <timestamp>
```
(the append-only ledger lists every action on the record, shown here as the first lines; `out/trace.json` logs the steps of each run: data, rank, explain, done).

## How to run
Requirements: Docker (Zetaris local platform), Node 22+, a Nightshift runtime token and NVIDIA key (see the hackathon Power guide).

```bash
# 1. Zetaris: start the platform, then run sql/zetaris.sql one statement at a time in the SQL Workspace
# 2. Agent
npm install
npm run setup                       # vendors the H-MEM reference into vendor/ (gitignored)
cp .env.example .env                # fill in ZETARIS_* and MODEL_* values; never commit .env
npx tsx patchwhy.ts run             # rank, remember, explain, gate, write out/report.html
npx tsx patchwhy.ts run --no-model  # same without the model call
npx tsx patchwhy.ts run --sample    # bundled snapshot, no credentials needed
npx tsx patchwhy.ts snapshot        # refresh data/sample_rows.json from Zetaris
npx tsx patchwhy.ts override A001 CVE-2024-3400 "accepted risk until the Friday window"
npx tsx patchwhy.ts audit mem-1     # ledger history of one memory
npx tsx patchwhy.ts compare         # three rankings side by side
npm test                            # unit tests + H-MEM integration test
```

Environment variables: `ZETARIS_REST_URL`, `ZETARIS_ORG_ID`, `ZETARIS_API_KEY`, `MODEL_BASE_URL`, `MODEL_API_KEY`, `NEMOTRON_MODEL`, optional `MODEL_ROUTE=meterless`.

Fill in **one** model route only (Nightshift: `MODEL_BASE_URL=http://127.0.0.1:8088/v1`, `NEMOTRON_MODEL=meterless/auto`). If a key appears twice in `.env` the first value wins, and PatchWhy prints a warning. The report states which endpoint was actually used and labels a non-local route as "direct".

![Nightshift compute receipt for a PatchWhy call: Nemotron 3.5 Super VL, 1152 in / 1633 out, $0.0000, receipt rcpt_req_a9a828q8](docs/nightshift-receipt.png)

*Signed Nightshift receipt for one real PatchWhy call (client `patchwhy`).*

## Demo Video
Demo video (3 min 23 s): https://youtu.be/gNwycIu_thg

## Sponsor technology
- **Zetaris:** three REST/inline sources joined by one SQL statement over the REST API; no data copied.
- **Meterless H-MEM:** stores evidence and analyst decisions with sources; a remembered decision changes the ranking (`test/hmem_integration.test.ts` proves this against the real engine) and each record has an audit ledger.
- **Meterless Nightshift + NVIDIA Nemotron:** the explanation model runs through the local Nightshift endpoint (`127.0.0.1:8088`, model `meterless/auto`); in my runs Nightshift served an NVIDIA Nemotron model (the report records the model name it returns). Nightshift issues a signed receipt per call (Proof tab). The HTTP response carries no cost figure, so the report says so rather than guessing; the signed receipt does: Nightshift's receipts list my runs under client `patchwhy`, served by Nemotron (3.5 Super VL 120B A12B in the receipt shown; other runs were served by Nemotron 3 Ultra 550B, as each report records), signed by `meterlessd` (Ed25519), with a cost of $0.0000 per call on my trial credits.

## Honest limits
- The asset inventory is synthetic. The scoring weights are my own and are not validated against real incident data.
- `compare` shows what different rankings put first. It is not a validation, and PatchWhy's score uses some of the signals it is compared on.
- The EPSS source holds only CVEs with EPSS above 0.88 (944 rows on 26 Oct 2026); KEV CVEs below that are not scored. FIRST's own "top 1000" ordering stopped working that day, which is why the filter is used (details in `docs/ZETARIS_USL.md`).
- The evidence gate checks citations and numbers, not whether a sentence is wise.

## Pre-existing code and AI assistance
- **Pre-existing (Meterless agentathon-starter, Apache-2.0):** `notebook.ts`, `src/engine.ts`, `src/llm.ts`, `seed/`, `images/`, the vendored H-MEM reference (`vendor/`, installed by `npm run setup`). The original README is `TEMPLATE_README.md`.
- **New work for this hackathon:** `patchwhy.ts`, `src/patchwhy_core.ts`, `src/overrides.ts`, `src/report.ts`, `test/`, `data/`, `sql/`, `docs/`.
- Built solo by Bharadwaj Rachuri. AI coding tool used: Claude. I reviewed, ran and tested all of it.

## Layout
`patchwhy.ts` CLI | `src/patchwhy_core.ts` scoring, counterfactuals, evidence gate | `src/overrides.ts` decisions read back from H-MEM | `src/report.ts` HTML report | `sql/zetaris.sql` Zetaris setup | `docs/ZETARIS_USL.md` USL write-up | `tools/zsql.ts` run SQL against Zetaris | `data/sample_rows.json` sample-mode snapshot | `data/assets.csv` synthetic inventory | `docs/agent-loop-spec.md` design notes
