# PatchWhy demo script (target 3:00, hard limit 4:00)

Record at 1080p. Show the terminal and one browser tab. Do a dry run first. Keep keys and `.env` off screen.

**0:00 Problem (20s).** "Security teams cannot patch everything. A severity score does not say which flaws attackers are using against companies like yours, and nobody can defend a ranking they cannot explain."

**0:20 Data (30s).** Zetaris SQL Workspace: show the three sources and the one joined query (sql/zetaris.sql). "KEV, EPSS and our asset inventory, joined in place by Zetaris. The inventory is synthetic."

**0:50 Run (40s).** `npx tsx patchwhy.ts run`. Point at: the model line (Nemotron through Nightshift), five findings from five different assets, the evidence gate result, and the "what would change this" line.

**1:30 Memory (45s).** `npx tsx patchwhy.ts override A001 CVE-2024-3400 "accepted risk until the Friday window"`, then run again. Show fw-edge-01 changing, the accepted-risk line citing the memory id, and `audit mem-1` showing the ledger. "H-MEM remembered a human decision with its source, and it changed the answer."

**2:15 Trust (30s).** Show a rejected model line if one appears (or the unit test that rejects an invented number). "The model only explains. Scoring is plain code, and a model sentence is shown only if it cites evidence and every number is in that evidence."

**2:45 Proof and close (15s).** Nightshift Proof tab: signed receipt for the Nemotron call. Open `out/report.html`. Close: "PatchWhy: a patch list you can defend."

Run `npm test` before recording so the H-MEM integration test passing is on screen at least once.
