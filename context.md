# context.md — VeriSIFT (Find Evil! Hackathon)

> Continuity file for Claude Code. Read this first at the start of every session.
> Update the "SESSION LOG" at the bottom before ending each session.

---

## 0. TL;DR for the agent
We are building **VeriSIFT**, a submission for the SANS *Find Evil!* hackathon.
It improves Protocol SIFT (an autonomous DFIR agent) by replacing its
**prompt-based** evidence guardrails with **architectural** ones (a typed MCP
server), plus a **self-correcting verification loop** that cross-checks findings
across disk artifacts. Scope is disk-image analysis only (depth over breadth).

---

## 1. The hackathon (hard facts)
- **Event:** Find Evil! (SANS Institute, on Devpost). Theme: autonomous AI
  incident-response agents on the SIFT Workstation via Protocol SIFT + MCP.
- **Submission deadline:** Jun 15, 2026, 11:45 PM EDT  (= Jun 16, 10:45 WIB).
- **Prizes:** $10k / $7.5k / $4.5k.
- **8 mandatory components** (missing ONE = elimination):
  1. Code repo (GitHub, public, MIT/Apache-2.0 visible in About)
  2. Demo video (<=5 min, live terminal + audio, >=1 self-correction shown)
  3. Architecture diagram (must distinguish architectural vs prompt guardrails)
  4. Written project description (Devpost story format)
  5. Dataset documentation
  6. Accuracy report (incl. evidence-integrity section)
  7. Try-it-out instructions
  8. Agent execution logs (traceable: finding -> exact tool call)
- **6 equally-weighted judging criteria:** Autonomous Execution (tiebreaker),
  IR Accuracy, Breadth/Depth, Constraint Implementation, Audit Trail, Usability.

## 2. Strategic thesis (WHY we can win despite zero DFIR background)
- The developer is a strong full-stack/systems engineer, NEW to DFIR.
- We do NOT compete on forensic depth. We compete on **system design**, where
  two criteria are won by engineering, not forensics:
    - **Constraint Implementation** — architectural guardrails beat prompt ones.
    - **Audit Trail** — disciplined structured logging.
- Protocol SIFT's real architecture (confirmed from its install.sh) is
  **Direct Agent Extension (#1)**: Claude Code + global CLAUDE.md + 5 Markdown
  "skills" (memory-analysis, plaso-timeline, sleuthkit, windows-artifacts,
  yara-hunting) + a PDF report script. Its guardrails are PROMPT-BASED.
- **Our angle (before/after):**
    1. Install baseline Protocol SIFT.
    2. Demonstrate a guardrail BYPASS (agent can be coaxed toward risky ops
       because only Markdown instructions restrain it).
    3. Replace with VeriSIFT typed MCP server — same bypass now IMPOSSIBLE
       (the destructive tool does not exist in the server).
  This maps directly onto judging criterion #4 ("tested for bypass").

## 3. Architecture (the combination = our novelty)
Custom MCP Server (#2)  +  Persistent Learning Loop (#7), fused:
- **Typed-tool MCP server** — exposes ONLY read functions. No execute_shell.
  Destructive ops impossible by construction (architectural guardrail).
- **Verification loop** — agent proposes findings as structured claims; the
  gate cross-checks each across artifacts; unsupported claims dropped
  (hallucinations caught), single-source labeled "inferred", >=2 sources
  "confirmed". Conflicts trigger a tightened re-run, capped at MAX_ITERATIONS.
- Why fused: the typed boundary makes corroboration MECHANICALLY checkable; the
  loop makes the typed tools self-correcting. Neither half alone gives both
  evidence-integrity AND self-correction.

### Trust boundary
Agent + verification logic sit ABOVE the boundary. Evidence access sits BELOW,
reachable ONLY through typed tools. No write path exists anywhere in code.

## 4. Repo layout (current scaffold — already built)
```
verisift/
  server.py            # MCP server: 4 typed tools + open_evidence
  evidence.py          # read-only handle, O_RDONLY, FAIL-CLOSED if writable, sha256 bracket
  audit.py             # JSONL structured execution log (component #8)
  verify.py            # verification gate + self-correction loop (TESTED, works)
  parsers.py           # << ONLY FILE LEFT TO IMPLEMENT — wire real DFIR tools here
  README.md            # setup + architecture + novelty
  ACCURACY_REPORT.md   # template with [FILL] placeholders
  LICENSE              # MIT
  requirements.txt     # mcp, regipy, python-evtx
```

### The 4 typed tools (disk image)
- `extract_mft_timeline()` -> analyzeMFT / MFTECmd     (file timeline)
- `analyze_prefetch()`      -> PECmd                    (execution evidence)
- `get_amcache()`           -> regipy                   (program presence)
- `parse_evtx()`            -> python-evtx              (event logs, e.g. 4688/4624)
Cross-check logic: an "execution" claim should be corroborated by
prefetch + amcache + evtx-4688; "presence" by mft + amcache; "logon" by evtx-4624.

## 5. Environment & setup order (DO NOT REORDER)
1. Download **SIFT Workstation OVA** from sans.org/tools/sift-workstation.
   (NOT github.com/teamdfir/sift — that's deprecated metadata/CLI, headless.)
2. Import OVA into VirtualBox/VMware. Allocate >=8GB RAM.
3. Boot SIFT VM, log in.
4. INSIDE the VM: `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
   (installs Claude Code + baseline skills to ~/.claude/)
5. Download starter evidence (Egnyte link from Protocol SIFT Slack).
6. `chmod 0444` the evidence image (enables our fail-closed read-only check).
7. Run baseline once, observe hallucinations (needed for accuracy report).
8. Drop verisift/ into the VM, register MCP server with Claude Code, iterate.

## 6. Build plan (remaining work, priority order)
- [ ] Implement `parsers.py::run_mft` first (timeline is the backbone). Keep the
      RETURN SHAPE exactly as documented so verify.py keeps working untouched.
- [ ] Implement run_prefetch, run_amcache, run_evtx.
- [ ] Get ONE finding corroborated across >=2 artifacts -> minimum viable demo.
- [ ] Record demo video AS SOON AS a self-correction sequence works (don't wait
      for perfection).
- [ ] Fill ACCURACY_REPORT.md [FILL]s with REAL numbers from the log. Never
      invent numbers — DFIR judges will spot it.
- [ ] Finalize README try-it-out steps.
- [ ] Confirm LICENSE shows in GitHub About section.

## 7. Hard rules / honesty guardrails (for the developer)
- Do NOT fabricate accuracy numbers or findings. Honest failure modes RAISE the
  score ("honesty valued over perfection").
- Keep scope to disk images. Resist adding memory/network — depth wins.
- Win is NOT guaranteed: it hinges on whether parsers produce ACCURATE findings
  on real data — the part the developer's zero-DFIR background makes riskiest.

## 8. SESSION LOG (newest at top — update before ending each session)
- 2026-06-14 (planning, in chat): Strategy locked (typed MCP + verify loop,
  before/after bypass narrative). Scaffold built & verify.py tested. Architecture
  diagram done. Accuracy report template done. NEXT: download SIFT OVA, start
  install, implement parsers.py::run_mft.
