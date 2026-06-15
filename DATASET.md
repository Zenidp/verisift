# VeriSIFT — Test Dataset

> Every artifact VeriSIFT is exercised against, with **source, SHA-256, and
> real-vs-synthetic provenance**. Nothing here is invented — hashes and counts
> are copied from the SIFT Workstation. Honesty is the point: a judge should be
> able to reproduce every number below.

We had **no disk image / E01 and no live case evidence** on this SIFT instance,
so this is a deliberately minimal corpus chosen to drive all four parsers and one
genuine, *computed* cross-artifact corroboration on the name `notepad.exe`.

---

## 1. Artifact inventory

| Artifact | File | Size (bytes) | Real / Synthetic | Source |
|---|---|---|---|---|
| **EVTX** | `test_data/evtx/Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx` | 69,632 | **REAL** | [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (med0x2e NTLM2SelfRelay capture) |
| **Amcache** | `test_data/amcache/amcache.hve` | 2,097,152 | **REAL** | regipy validated Win10 `Amcache.hve` fixture |
| **MFT** | `test_data/mft/MFT_extracted.bin` | 27,648 | **REAL** | `$MFT` carved (TSK `icat`) from a synthetic NTFS image built with `mkntfs` |
| **Prefetch** | `test_data/prefetch/NOTEPAD.EXE-07476F82.pf` | 336 | **SYNTHETIC** | Built byte-accurately from the libscca v30 format spec by `analysis/make_test_prefetch.py` |

### SHA-256

```
26fd9de9bc19b4af5308c30b51d2ca17b0518f8c89826fceb092c86a01f42b2b  evtx/Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx
bd77d59379c4be223b41aa69dddae52269e8af78f429eabee89b56e6bcd52833  amcache/amcache.hve
be5f1db6e6ea7515c76bfdbaf2c7bf5154ea9818321c948514cda1a1c6db04d1  mft/MFT_extracted.bin
883f6d8284441bdcbbcb9529486a988bc151ebbb743cb146b452e79c3f022020  prefetch/NOTEPAD.EXE-07476F82.pf
```

All four files are committed mode **`0444`** (read-only) — required by the
fail-closed `EvidenceHandle`.

---

## 2. What each artifact actually contains (verified by our parsers)

| Artifact | Parser → result on this run |
|---|---|
| **EVTX** | `parse_evtx(channel='Security', event_ids=[4624,4688])` → **5 events**: 4× EID 4624 logon (`WINLAB.LOCAL\Administrator`, logon type 3, from `192.168.1.219`) + 1× EID 4688 process-create of `C:\Windows\System32\notepad.exe`. |
| **Amcache** | `get_amcache()` → **1367 entries**; includes `c:\windows\system32\notepad.exe` (the corroborating hit for `notepad.exe`). |
| **MFT** | `extract_mft_timeline()` → **18 records**, all NTFS system metafiles (`$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef`, …). **No user executables** — so it correctly contributes **no** corroboration for `notepad.exe`. |
| **Prefetch** | `analyze_prefetch()` → **1 entry**: `NOTEPAD.EXE`, `run_count=7`, 2 valid last-run times (`2026-06-12T09:15:30`, `2026-06-13T14:42:05`); 6 unused/epoch-zero slots skipped. |

The genuine, computed correlation that makes `notepad.exe` `[CONFIRMED]`:
```
notepad.exe -> HIT in amcache=['c:\windows\system32\notepad.exe', 'notepad.exe']  prefetch=['NOTEPAD.EXE']
```
(EVTX-4688 supplies the originating source; amcache + prefetch are the
corroborators; MFT honestly contributes none.)

---

## 3. Real vs synthetic — and why one is synthetic

**Three of four artifacts are real.** Only the prefetch file is synthetic, and we
disclose exactly why:

- There was **no Windows evidence on this SIFT instance** to pull a real `.pf`
  from, and network DNS on the box was unreliable (UDP DNS blocked; see project
  notes). Real public `.pf` samples (e.g. DFIRArtifactMuseum) are packed inside
  `.7z`/`.rar` archives that we could not reliably fetch.
- So `analysis/make_test_prefetch.py` builds a **byte-accurate Windows-10 v30**
  prefetch file directly from the libscca on-disk format specification.
- Crucially, it is parsed by the **real, court-vetted `pyscca` (libscca) parser** —
  the same tool used on genuine evidence. The *parser path is genuine*; only the
  input bytes are synthesized.

**Why it does not weaken the demo:** the `[CONFIRMED] notepad.exe` verdict rests on
**two independent REAL artifacts** (EVTX EID 4688 + the real Amcache hive). The
synthetic prefetch is only a *third* corroborator. Discount it entirely and the
finding is still confirmed on two real sources.

> **Honesty caveat:** these are independently-sourced fixtures, **not** four
> artifacts carved from one compromised host. The `correlate()` match is a real
> computation; the "case" around it is a methodology demonstration. See
> [`ACCURACY_REPORT.md`](ACCURACY_REPORT.md) §0.

---

## 4. Tool / environment versions (for reproducibility)

| Component | Version |
|---|---|
| Python | 3.12.3 |
| mcp (MCP SDK) | 1.27.2 |
| python-evtx | 0.8.1 |
| regipy | 6.2.1 |
| pyscca / libscca | 20250915 |
| MFTECmd (EZ Tools, dotnet) | 1.3.0.0 |

---

## 5. How to reproduce

```bash
# 0. Install dependencies
pip3 install -r requirements.txt        # mcp · regipy · python-evtx · pyscca
#    MFTECmd (EZ Tools / dotnet) and The Sleuth Kit must be on PATH

# 1. Verify the artifact hashes match this document
cd /cases/verisift
sha256sum \
  "test_data/evtx/Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx" \
  test_data/amcache/amcache.hve \
  test_data/mft/MFT_extracted.bin \
  test_data/prefetch/NOTEPAD.EXE-07476F82.pf

# 2. (Optional) Rebuild the synthetic prefetch from the format spec
python3 analysis/make_test_prefetch.py   # regenerates the v30 .pf byte-for-byte

# 3. Run the full pipeline (writes the audit log used in the Accuracy Report)
export VERISIFT_LOG=/cases/verisift/exports/execution_log.jsonl
rm -f "$VERISIFT_LOG"
python3 demo_investigation.py

# 4. Inspect the audit trail (one JSONL record per tool call)
cat "$VERISIFT_LOG"
```

Expected end state (matches `ACCURACY_REPORT.md`):
```
[CONFIRMED] execution notepad.exe    conf=1.0  supports=['amcache', 'evtx_4688', 'prefetch']
[INFERRED ] logon     Administrator  conf=0.5  supports=['evtx_4624']
injected test claim dropped: 1       (EVILCORP.EXE)
```

---

## 6. Licensing / attribution

- The EVTX sample originates from **EVTX-ATTACK-SAMPLES** (sbousseaden), used here
  for research/testing under its repository license. Only the single file needed
  for the demo is vendored; the upstream repo is the canonical source.
- The Amcache hive is a regipy test fixture.
- The MFT and prefetch artifacts were generated locally (see above) and carry no
  third-party data.
