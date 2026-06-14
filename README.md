# VeriSIFT — Read-only by architecture, self-correcting by design

A purpose-built MCP server that turns Protocol SIFT into an autonomous,
**spoliation-proof**, **self-correcting** disk-image triage agent for the
SANS *Find Evil!* hackathon.

> **Architectural pattern:** Custom MCP Server (#2) + Persistent Learning Loop (#7).
> Guardrails are enforced *by construction*, not by prompt.

## Why this design wins on the rubric

| Judging criterion | How VeriSIFT addresses it |
|---|---|
| Autonomous Execution (tiebreaker) | Verification loop re-runs and tightens parameters without human input (`verify.py`). |
| IR Accuracy | Multi-artifact corroboration drops unsupported claims and labels single-source ones as *inferences*. |
| Breadth & Depth | Deep on one data type (disk image), with cross-artifact correlation (MFT × prefetch × amcache × evtx). |
| **Constraint Implementation** | No shell tool exists. Evidence opened `O_RDONLY`, **fails closed** if writable (`evidence.py`). |
| **Audit Trail** | Every tool call → one JSONL record with run_id, seq, timestamp, duration (`audit.py`). |
| Usability | Single `pip install`, four typed tools, documented parser wiring points. |

## Architecture

```
        ┌────────────┐   typed tool calls    ┌────────────────────┐
        │  Agent     │ ───────────────────►  │  VeriSIFT MCP      │
        │ (Claude    │                       │  server.py         │
        │  Code /    │ ◄─────────────────── │  - open_evidence   │
        │  OpenClaw) │   structured JSON      │  - extract_mft_... │
        └─────┬──────┘                       │  - analyze_prefetch│
              │ findings                      │  - get_amcache     │
              ▼                               │  - parse_evtx      │
        ┌────────────┐                        └─────────┬──────────┘
        │ verify.py  │  cross-artifact                  │ read-only
        │ gate+loop  │  corroboration            ┌──────▼─────────┐
        └─────┬──────┘                           │ evidence.py    │
              │ iteration traces                 │ O_RDONLY,      │
              ▼                                   │ fail-closed    │
        ┌────────────┐                           └──────┬─────────┘
        │ audit.py   │  JSONL execution log             │
        └────────────┘                           ┌──────▼─────────┐
                                                  │ parsers.py →   │
                                                  │ TSK/PECmd/...  │
                                                  └──────┬─────────┘
                                                   read-only image
   ── trust boundary ──────────────────────────────────────────────
   ARCHITECTURAL guardrail: agent cannot reach the image except through
   typed tools; no write path exists in code. NOT a prompt instruction.
```

## Setup (on the SIFT Workstation)

```bash
# 1. Install SIFT + Protocol SIFT first (see hackathon resources).
# 2. Clone this repo into the SIFT VM, then:
python3 -m venv .venv && source .venv/bin/activate
pip install mcp regipy python-evtx        # + analyzeMFT, TSK on PATH
# 3. Make evidence read-only (fail-closed enforcement):
chmod 0444 /cases/case01.E01
# 4. Register the server with your agent (Claude Code MCP config) and run.
```

## Try it out (for judges)

```bash
# Point the agent at the provided starter image and ask it to triage.
# The agent will: open_evidence -> run tools -> verify -> iterate.
# Outputs:
#   /cases/out/execution_log.jsonl   (audit trail, component #8)
#   findings + iteration traces        (printed structured narrative)
```

## What's novel (required: document novel contribution)

The hackathon lists #2 and #7 as separate patterns. VeriSIFT **fuses** them:
the typed-tool boundary makes corroboration *meaningful* (every claim is
mechanically checkable), and the loop makes the typed tools *self-correcting*.
Neither half delivers both evidence-integrity and self-correction alone.

## License
MIT (see LICENSE).
