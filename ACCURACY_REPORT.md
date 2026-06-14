# VeriSIFT — Accuracy Report

> Self-assessment of findings accuracy on the *Find Evil!* starter evidence.
> **Honesty over perfection** — documented failure modes are signal, not weakness.
>
> **HOW TO USE THIS TEMPLATE:** every `[FILL]` is a placeholder you replace with
> real numbers from your test run. Do NOT invent numbers — run the agent against
> the provided evidence, read the JSONL execution log, and count.

---

## 1. Test setup

- **Evidence used:** [FILL — e.g. "case01.E01, provided SANS starter disk image"]
- **Evidence source:** SANS *Find Evil!* starter dataset (Egnyte link, provided at launch)
- **SHA-256 of image (before run):** [FILL — from open_evidence() output]
- **SHA-256 of image (after run):** [FILL — from reverify_integrity()]
- **Integrity preserved:** [FILL — YES if hashes match; this is your spoliation proof]
- **Agent / framework:** [FILL — e.g. "Claude Code + VeriSIFT MCP server"]
- **Tools exercised:** extract_mft_timeline, analyze_prefetch, get_amcache, parse_evtx
- **Ground truth source:** [FILL — provided case notes, OR your own manual verification]

## 2. Findings summary

| # | Finding (claim) | Status | Confidence | Corroborating artifacts | Traceable to (log seq) |
|---|---|---|---|---|---|
| 1 | [FILL] | confirmed / inferred | [FILL] | [FILL] | seq [FILL] |
| 2 | [FILL] | [FILL] | [FILL] | [FILL] | seq [FILL] |
| 3 | [FILL] | [FILL] | [FILL] | [FILL] | seq [FILL] |

*Every row's last column must point to a line in `execution_log.jsonl`. That is
the audit-trail guarantee — a judge can verify any finding against the exact tool
call that produced it.*

## 3. Accuracy metrics

- **Total claims proposed (iteration 1):** [FILL]
- **Confirmed (≥2 independent artifacts):** [FILL]
- **Inferred (single-source, labeled as such):** [FILL]
- **Dropped as unsupported (caught hallucinations):** [FILL]
- **False positives that survived to final output:** [FILL — be honest]
- **Known missed artifacts:** [FILL — what a human analyst would catch that you didn't]

## 4. Self-correction evidence

Summarize what changed between iterations (pull from iteration traces in the log):

- **Iteration 1 → 2:** [FILL — e.g. "GHOST.EXE dropped (no corroboration);
  MALWARE.EXE promoted from inferred to confirmed after amcache + evtx-4688 agreed"]
- **Iteration 2 → 3 (if any):** [FILL]
- **Stopping condition reached:** [FILL — "no conflicts remaining" or "max-iterations cap"]

This section maps directly to the judging criterion *Autonomous Execution Quality*.

## 5. Evidence integrity approach (REQUIRED section)

VeriSIFT prevents original-data modification **by construction, not instruction**:

1. **No write path exists.** The MCP server exposes only typed read functions.
   There is no `execute_shell` / `run_command` tool, so the agent physically
   cannot issue a destructive command — the capability is absent from the server.

2. **Fail-closed read-only check.** `evidence.py` refuses to proceed if the image
   has any write bit set (owner/group/other), and opens it `O_RDONLY`. If the
   evidence is writable, analysis aborts.

3. **Hash bracketing.** The image is SHA-256 hashed before and after analysis.
   A mismatch would be surfaced loudly. (Result for this run: section 1.)

### Spoliation test performed
[FILL — describe what you tried. Example: "Attempted to prompt the agent to delete
or modify the image. Because no write tool is exposed, the agent could only call
read functions; no modification was possible. Post-run hash matched pre-run hash."]

### Failure modes found (document honestly)
[FILL — anything that went wrong. Examples that are GOOD to report:
 - "Parser X mis-handled a timezone, producing a 1-hour-off timestamp on N records"
 - "Single-source amcache entries were occasionally over-trusted before the loop ran"
 - "Tool Y timed out on the full $MFT; needed time-window bounding"
 Reporting these RAISES your score on IR Accuracy honesty.]

## 6. Limitations

- Scope is disk-image artifacts only (MFT, prefetch, amcache, EVTX). Memory and
  network captures are out of scope by design — depth over breadth.
- Corroboration rules are heuristic; a sophisticated anti-forensic actor could
  defeat cross-artifact agreement. [FILL — note any others you observe.]
