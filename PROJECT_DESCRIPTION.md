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

We want to be honest about what we actually tested. Protocol SIFT itself was **not
installed on our SIFT instance**, so we did *not* run a head-to-head prompt-bypass
of the baseline — we will not claim an experiment we didn't perform. Instead we
verified the VeriSIFT guarantee directly, at the level where it lives:

- **The destructive capability is absent.** There is no `execute_shell` /
  `run_command` tool on the server — `git grep` finds no write path to evidence.
  The agent can only call typed read functions.
- **Fail-closed, verified empirically.** We copied a fixture to a *writable* temp
  file (mode `0644`) and called `EvidenceHandle.open()`. It was **refused** with
  `ReadOnlyViolation`; only after `chmod 0444` did it open. (Reproducible — see the
  spoliation test in the Accuracy Report.)
- **No mutation across a full run.** The primary evidence SHA-256 was **identical
  before and after** the end-to-end run (`26fd9de9…`), and all fixtures are mode
  `0444`.

This is the heart of the submission: the guarantee is *construction*, not
*instruction* — and we verified the construction rather than asserting a baseline
comparison we couldn't run.

## Challenges we ran into

- **Zero DFIR background.** We had to learn what artifacts actually corroborate
  each other (why prefetch + amcache + 4688 together beat any one alone). What
  surprised us: a bare `$MFT` carved from a fresh NTFS volume contains only system
  metafiles (`$Boot`, `$LogFile`, …) and **no** user executables — so when our
  `correlate()` honestly returned *no* MFT hit for `notepad.exe`, that was correct
  behavior, not a bug. It taught us that "no corroboration from artifact X" is a
  real signal, not a failure to be papered over.
- **Raw tool output is huge.** Returning unparsed DFIR output floods the context
  window. We parse to structured JSON inside the server before it reaches the LLM.
- **Stopping the loop.** Self-correction can spiral; we added a hard iteration cap
  (`MAX_ITERATIONS = 4`) and a "nothing left to improve" stop condition.
- **Real bugs we hit on the workstation.** (1) `MFTECmd` writes a UTF-8 BOM on the
  first CSV header field, so our column lookup silently missed until we read the
  CSV as `utf-8-sig`. (2) `pyscca` has no `get_number_of_last_run_times()`, so our
  first prefetch parser produced phantom year-1601 timestamps from unused run-time
  slots; we fixed it by probing `get_last_run_time(i)` positionally and skipping
  epoch-zero slots. Both were caught only by checking parsed output against the raw
  artifact.

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
Accuracy Report for the measured counts. On our test run (`run_id
r-20260615-041925`) the pipeline behaved exactly as designed: of 3 proposed claims
it **confirmed 1** (`notepad.exe`, corroborated across amcache + evtx-4688 +
prefetch), **labeled 1 as inferred** (single-source `Administrator` logon), and
**dropped 1** injected false claim (`EVILCORP.EXE`) — 0 false positives surviving
to the final report, with the primary evidence hash unchanged before/after. Note
this is a fixture corpus, not a real intrusion: it proves the pipeline's logic, not
real-world malware-detection accuracy.

## Built with

python · model context protocol (mcp) · claude code · sans sift workstation ·
analyzeMFT · PECmd · regipy · python-evtx
