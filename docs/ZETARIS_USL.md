# PatchWhy and the Zetaris Unified Semantic Layer (USL)

This follows the Zetaris evaluation criteria (Build a USL, then Reflect on it). Everything below was run in my local Zetaris on 26 Oct 2026; counts are the real results.

## 1. Build a Unified Semantic Layer

### 1a. Use case and data sources
**Use case:** "Which known-exploited vulnerabilities should we patch first, and why?" for a small security team.

| # | Source | Type | Zetaris object |
|---|---|---|---|
| 1 | CISA Known Exploited Vulnerabilities (public JSON) | REST | `VULN_REST.kev_catalog` |
| 2 | FIRST EPSS exploitation probabilities (public API) | REST | `VULN_REST.epss_hi` |
| 3 | Asset inventory (synthetic, a made-up company; `data/assets.csv`) | inline table | `vulnstore.assets` |

Three sources, queried in place. Nothing is copied into a separate store.

### 1b. Onboarding, verification and exploratory queries
DDL for the sources is in [`sql/zetaris.sql`](../sql/zetaris.sql) (REST tables, the `vulnstore` container, three views). Exploratory queries, 2 to 3 per source, with results:

**KEV**
```sql
SELECT count(*) AS kev_rows, count(DISTINCT vendor) AS vendors, min(date_added) AS first_added,
       max(date_added) AS last_added, sum(CASE WHEN ransomware = 'Known' THEN 1 ELSE 0 END) AS ransomware_known
FROM vulnstore.kev
-- 1756 rows, 291 vendors, first added 2021-11-03, last added 2026-10-23, 361 with known ransomware use
```
```sql
SELECT a.asset_id, a.vendor, a.product, k.cve FROM vulnstore.assets a
JOIN vulnstore.kev k ON a.vendor = k.vendor AND a.product = k.product LIMIT 5
-- A001 / Palo Alto Networks / PAN-OS rows, e.g. CVE-2024-3400: vendor and product names match the inventory
```

**EPSS**
```sql
SELECT count(*) AS epss_rows, min(epss) AS min_epss, max(epss) AS max_epss, avg(epss) AS avg_epss FROM vulnstore.epss
-- 944 rows, min 0.88003, max 0.99999, average 0.956
```
```sql
SELECT e.cve, e.epss, k.cve AS kev_cve FROM vulnstore.epss e LEFT JOIN vulnstore.kev k ON k.cve = e.cve ORDER BY e.epss DESC LIMIT 8
-- found a real source problem (see "What went wrong" below)
```

**Assets (synthetic)**
```sql
SELECT environment, count(*) AS assets, sum(CASE WHEN patch_status = 'unpatched' THEN 1 ELSE 0 END) AS unpatched,
       sum(CASE WHEN internet_facing = 'yes' THEN 1 ELSE 0 END) AS internet_facing
FROM vulnstore.assets GROUP BY environment
-- production 15 assets / 11 unpatched / 11 internet-facing; staging 1 / 1 / 0; development 1 / 1 / 0
```

### 1c. The USL, its DDL, queries showing it is active, and a data quality rule
**The USL** is the `vulnstore` container with three views (`kev`, `epss`, `assets`). One SQL statement joins them; this is the statement PatchWhy runs (`SQL` in `patchwhy.ts`):

```sql
SELECT a.asset_id, a.hostname, a.environment, a.internet_facing, a.criticality, k.cve, e.epss,
       k.ransomware, k.due_date, k.vendor, k.product
FROM vulnstore.assets a
JOIN vulnstore.kev k ON a.vendor = k.vendor AND a.product = k.product
JOIN vulnstore.epss e ON k.cve = e.cve
WHERE a.patch_status = 'unpatched'
```

**USL active, query 1: join summary**
```sql
SELECT count(*) AS pairs, count(DISTINCT a.asset_id) AS assets_affected,
       sum(CASE WHEN k.ransomware = 'Known' THEN 1 ELSE 0 END) AS ransomware_pairs
FROM vulnstore.assets a JOIN vulnstore.kev k ON a.vendor = k.vendor AND a.product = k.product
JOIN vulnstore.epss e ON k.cve = e.cve WHERE a.patch_status = 'unpatched'
-- 36 asset/vulnerability pairs, 13 assets affected, 29 pairs with known ransomware use
```
**USL active, query 2: exposure per host**
```sql
SELECT a.hostname, a.internet_facing, count(*) AS exploited_cves FROM vulnstore.assets a
JOIN vulnstore.kev k ON a.vendor = k.vendor AND a.product = k.product
JOIN vulnstore.epss e ON k.cve = e.cve WHERE a.patch_status = 'unpatched'
GROUP BY a.hostname, a.internet_facing ORDER BY exploited_cves DESC LIMIT 5
-- mail-01 11, fw-edge-01 6, wiki-stg 3, wiki-01 3, vpn-gw-01 2
```
**USL active, query 3:** the full ranked statement above, which PatchWhy executes on every run and which the report prints with its row count and time.

**Data quality rule (executed):** no nulls in the keys, EPSS between 0 and 1, criticality between 1 and 5.
```sql
SELECT (SELECT count(*) FROM vulnstore.epss WHERE epss < 0 OR epss > 1 OR cve IS NULL) AS epss_violations,
       (SELECT count(*) FROM vulnstore.kev WHERE cve IS NULL OR vendor IS NULL OR product IS NULL OR due_date IS NULL) AS kev_violations,
       (SELECT count(*) FROM vulnstore.assets WHERE criticality < 1 OR criticality > 5 OR asset_id IS NULL) AS asset_violations
-- 0, 0, 0
```

## 2. Reflect on the USL

### 2a. How the USL saved time versus a hand-coded approach
Without the USL I would have written three fetch-and-parse scripts (KEV JSON with a nested `vulnerabilities` array, the EPSS API with string-typed numbers, a CSV loader), a join in code with vendor and product matching, and a way to refresh it. With Zetaris I registered the two REST sources and one inventory table, and the join is one SQL statement the agent runs, with the SQL shown in the report so a reader can check it. My own estimate, not a measured benchmark: roughly half a day of glue code became about an hour of SQL, and the join logic is now readable by someone who does not read TypeScript. I did not build the hand-coded version to compare.

### 2b. How the USL helped, and where it did not
- **Helped:** one access point for three sources; exploration by SQL before writing any agent code; the evidence rows behind every explanation come straight from the join, which makes the "why" auditable.
- **Did not help / cost me time:** FIRST's `order=!epss` ordering stopped working on 26 Oct (the API returned CVEs sorted by id, not by score), which silently emptied the join. The REST source gave no error, only 0 rows. I only found it by running the per-source count queries above.
- **Forecast:** for a team with ten sources instead of three, the saving would grow with each source that needs its own parser.

### 2c. How to make the USL stronger (as a requirement to Zetaris)
1. **Fail loudly on an empty join.** When a REST source returns rows but a join returns 0, the USL should warn which side has no matching keys. I lost time to a silent empty result.
2. **Declarative data quality rules.** The rule I ran is a hand-written `SELECT`. A rule attached to the view (`NOT NULL`, ranges) that runs on refresh and reports violations would remove that step.
3. **Versioned REST source definitions with a pinned query.** The EPSS endpoint changed behaviour without notice; a recorded sample response per source would let the USL detect that a feed's shape or ordering changed.
4. **Safe re-create.** `CREATE OR REPLACE` for views worked for me; the same for REST tables would make fixes like the EPSS one a single statement.

## What went wrong (kept for honesty)
On 26 Oct 2026 the EPSS source `order=!epss&limit=1000` returned low-score 2026 CVEs sorted by id, so no known-exploited CVE matched and the join was empty. I replaced it with `epss-gt=0.88&limit=1000` (944 rows), recreated the REST table as `epss_hi` and redefined the `epss` view. The earlier run used for the demo video was taken before this change; its results (mail-01 at 115, rank 1 to 5 without internet exposure) are the same in the fixed source.
