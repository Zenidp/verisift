# VeriSIFT

**Read-only by architecture. Self-correcting by design.**

A typed-MCP incident-response agent that makes evidence spoliation *impossible*
instead of merely *forbidden* — and catches its own hallucinations before a human
ever sees them.

---

## Inspiration

Protocol SIFT proves something important: connect an AI agent to the SANS SIFT
Workstation and it can triage a disk image at machine speed. But when we read how
it actually works, we found its guardrails are **prompt-based**. The agent is
*told* not to modify evidence. In incident response, "the model was instructed not
to" is not a chain-of-custody guarantee a practitioner can stand behind in court.

We came at this as systems engineers, not DFIR veterans. That turned out to be the
right lens. The hardest problems here aren't forensic — they're architectural:
*How do you make a destructive action impossible rather than discouraged? How do
you make every finding traceable? How does an agent know when it's wrong?*

## What it does

VeriSIFT extends Protocol SIFT for autonomous disk-image triage with two layers
that lock together:

1. **A typed MCP server (architectural guardrail).** Instead of giving the agent a
   generic `execute_shell` tool, VeriSIFT exposes only a small set of typed,
   read-only functions: `extract_mft_timeline()`, `analyze_prefetch()`,
   `get_amcache()`, `parse_evtx()`. The agent *cannot* run a destructive command
   because that capability does not exist in the server. Evidence is opened
   `O_RDONLY` and the server refuses to start analysis if the image is writable
   (fail-closed). The image is SHA-256 hashed before and after every run.

2. **A self-correcting verification loop.** The agent proposes findings as
   structured claims. A verification gate cross-checks each claim across
   independent artifacts — an "execution" claim should be corroborated by
   prefetch, amcache, and Event ID 4688. Claims with no support are dropped as
   hallucinations; single-source claims are labeled "inferred"; multi-source
   claims become "confirmed." Conflicts trigger a tightened re-run, capped to
   prevent runaway iteration. Every iteration is logged.

The result: an agent that physically cannot harm evidence, and that distinguishes
what it *confirmed* from what it merely *inferred* — with a full audit trail.

## How we built it

- **Language:** Python, using the MCP SDK for the server and standard DFIR tools
  (analyzeMFT/MFTECmd, PECmd, regipy, python-evtx) wrapped behind typed functions.
- **`evidence.py`** enforces the read-only guarantee at the OS level (fail-closed
  on any write bit) and brackets each run with SHA-256 hashes.
- **`verify.py`** implements the corroboration rules and the bounded
  self-correction loop. We unit-tested the loop with simulated findings before
  touching real evidence, confirming it drops an unsupported claim and promotes a
  single-source claim to "confirmed" once corroboration appears.
- **`audit.py`** writes one structured JSONL record per tool call — run id,
  sequence number, timestamp, arguments, result counts, duration — so any finding
  traces back to the exact execution that produced it.
- We installed the baseline Protocol SIFT first to establish a reference point,
  then built VeriSIFT as the architectural replacement for its prompt-based
  evidence handling.

## The before/after that matters most

We tested the baseline's prompt-based guardrail for bypass, then the same scenario
against VeriSIFT:

- **Baseline (prompt-based):** [FILL — describe what you observed when you probed
  whether the agent could be steered toward a risky operation; document honestly.]
- **VeriSIFT (architectural):** the same attempt is impossible — the destructive
  tool is simply absent from the server. Post-run hash matched pre-run hash.

This is the heart of the submission: moving the guarantee from *instruction* to
*construction*.

## Challenges we ran into

- **Zero DFIR background.** We had to learn what artifacts actually corroborate
  each other (why prefetch + amcache + 4688 together beat any one alone). [FILL —
  add a specific thing that surprised you during testing.]
- **Raw tool output is huge.** Returning unparsed DFIR output floods the context
  window. We parse to structured JSON inside the server before it reaches the LLM.
- **Stopping the loop.** Self-correction can spiral; we added a hard iteration cap
  and a "nothing left to improve" stop condition.
- [FILL — a real bug or dead-end you hit on the SIFT Workstation.]

## What we learned

- Architectural constraints beat prompt constraints whenever the stakes are real.
  A tool that doesn't exist can't be misused.
- Corroboration is only *meaningful* when each source is independently, mechanically
  checkable — which is exactly what typed tools give you. The two layers needed
  each other.
- Honest uncertainty ("inferred," not "confirmed") is more useful to a responder
  than confident-sounding output.

## What's next

- Extend the typed-tool set deeper within disk artifacts (registry hives, shimcache,
  USN journal) — more corroboration sources, same architecture.
- Optional memory-capture tools as a second, clearly-bounded module.
- Package the corroboration rules so practitioners can add their own artifact
  cross-checks without touching the loop.

## Honest limitations

Scope is disk-image artifacts by design — depth over breadth. The corroboration
rules are heuristic and a determined anti-forensic actor could defeat cross-artifact
agreement. Accuracy on real evidence depends on the underlying parsers; see our
Accuracy Report for measured false-positive and missed-artifact counts rather than
claims. [FILL — one-line honest summary of measured accuracy once you have it.]

## Built with

python · model context protocol (mcp) · claude code · sans sift workstation ·
analyzeMFT · PECmd · regipy · python-evtx
