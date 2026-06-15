# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Course:** SANS FOR508 — Advanced Incident Response, Threat Hunting & Digital Forensics
**Scenario:** Stark Research Labs (SRL) — Lab 1.1 APT Incident Response Challenge

---

## Case Overview

| Field | Value |
|-------|-------|
| **Client** | Stark Research Labs (SRL) |
| **Domain** | SHIELDBASE (Windows Server 2022, 2022 DFL) |
| **Threat Actor** | CRIMSON OSPREY (state-level APT) |
| **Incident Declared** | 2023-01-24 |
| **Your Role** | External IR consultant |
| **Initial Responders** | Roger Sydow (IT Admin), Clint Barton (IT Security Analyst) |

---

## Evidence Files

| File | System | Notes |
|------|--------|-------|
| `/cases/srl/base-dc-cdrive.E01` | dc01 — Domain Controller | C: drive (~12.5 GB) |
| `/cases/srl/base-rd01-cdrive.E01` | rd01 — Remote Desktop Server | C: drive (~16.6 GB) — **primary compromise host** |
| `/cases/memory/rd01-memory.img` | rd01 | RAM capture (5 GB, primary analysis image) |
| `/cases/srl/base-rd_memory.img` | rd01 | RAM capture (3 GB, baseline-era image) |
| `/cases/srl/base-dc_memory.img` | dc01 | RAM capture (5 GB) |

**Read-only — do NOT modify evidence files.**
Output all analysis to `./analysis/`, `./exports/`, or `./reports/` (relative to `/cases/srl/`).

---

## Common Commands

### Mount E01 images (read-only)

```bash
# Mount rd01 C: drive
sudo mkdir -p /mnt/ewf_rd01 /mnt/rd01
sudo ewfmount /cases/srl/base-rd01-cdrive.E01 /mnt/ewf_rd01
sudo mount -o ro,loop,noatime /mnt/ewf_rd01/ewf1 /mnt/rd01

# Mount dc01 C: drive
sudo mkdir -p /mnt/ewf_dc01 /mnt/dc01
sudo ewfmount /cases/srl/base-dc-cdrive.E01 /mnt/ewf_dc01
sudo mount -o ro,loop,noatime /mnt/ewf_dc01/ewf1 /mnt/dc01

# Unmount when done
sudo umount /mnt/rd01 && sudo umount /mnt/ewf_rd01
sudo umount /mnt/dc01 && sudo umount /mnt/ewf_dc01
```

### Volatility 3 (memory — rd01)

```bash
VOL="python3 /opt/volatility3-2.20.0/vol.py"
IMG="/cases/memory/rd01-memory.img"

# Human-readable process tree
$VOL -f $IMG -r pretty windows.pstree | cut -d '|' -f 1-11

# All processes incl. exited
$VOL -f $IMG windows.psscan | grep -v "N/A"

# Command lines
$VOL -f $IMG windows.cmdline | tee ./exports/cmdline.txt

# Process SIDs
$VOL -f $IMG windows.getsids | tee ./exports/getsids.txt

# Network connections
$VOL -f $IMG -r csv windows.netstat | tee ./exports/netstat.csv

# DLL list for a specific PID
$VOL -f $IMG -r csv windows.dlllist --pid 1912 | tee ./exports/dlllist-stun.csv
```

### Memory Baseliner (process / service / driver diff)

```bash
python3 /opt/memory-baseliner/baseline.py \
  -proc -i /cases/memory/rd01-memory.img \
  --loadbaseline \
  --jsonbaseline /cases/memory/baseline/Win11x64_proc_baseline.json \
  -o ./exports/proc_baseline_diff.csv
```

### EZ Tools (dotnet, Windows artifacts from mounted image)

```bash
# MFTECmd — parse MFT
dotnet /opt/zimmermantools/MFTECmd.dll \
  -f /mnt/rd01/\$MFT \
  --csv ./exports/ --csvf rd01-mft.csv

# EvtxECmd — parse event logs
dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll \
  -d /mnt/rd01/Windows/System32/winevt/Logs/ \
  --csv ./exports/ --csvf rd01-evtx.csv \
  --maps /opt/zimmermantools/EvtxeCmd/Maps/

# RECmd — registry hives
dotnet /opt/zimmermantools/RECmd/RECmd.dll \
  -d /mnt/rd01/Windows/System32/config/ \
  --csv ./exports/ --csvf rd01-registry.csv

# AmcacheParser
dotnet /opt/zimmermantools/AmcacheParser.dll \
  -f /mnt/rd01/Windows/AppCompat/Programs/Amcache.hve \
  --csv ./exports/ --csvf rd01-amcache.csv
```

### Sleuth Kit (filesystem, no mount required)

```bash
# List files — rd01 image
fls -r -o 2048 /mnt/ewf_rd01/ewf1 | grep -i "stun"

# Extract a file by inode
icat -o 2048 /mnt/ewf_rd01/ewf1 <INODE> > ./exports/stun_extracted.exe

# Verify image
ewfverify /cases/srl/base-rd01-cdrive.E01
```

---

## Network Topology

| Network | Subnet | Key Hosts |
|---------|--------|-----------|
| **Management** | 172.16.8.0/24 | log01, assess01/02, sft01, trust01, adusa01 (ELF01 syslog) |
| **Services** | 172.16.4.0/24 | dc01, file01, exchange01 (Exchange 2019), proxy01 (Squid), dev01, sql01 |
| **Business Line** | 172.16.7.0/24 | wksta01–wksta10 (Windows 11) |
| **R&D** | 172.16.6.0/24 | rd01–rd10 (Windows 11); lateral movement target: **172.16.6.12** |
| **DMZ** | 172.16.19.0/24 | dns01, ftp01, smtp01 |
| **VPN Client** | 172.16.30.0/24 | Remote workers |

**External attacker IP:** 172.15.1.20

---

## Domain Accounts

| Account | Role |
|---------|------|
| `rsydow-a` | Domain Admin — Roger Sydow (IT Admin) |
| `cbarton-a` | Domain Admin — Clint Barton (IT Security Analyst) |
| `srl.admin` | Emergency Domain Admin (break-glass) |
| `srladmin` | Local Admin — all workstations |

---

## Known IOCs

### Confirmed Malware

| Indicator | Type | Detail |
|-----------|------|--------|
| `STUN.exe` | Malware binary | `C:\Windows\System32\STUN.exe`, PID 1912, parent svchost.exe PID 1244 |
| `msedge.exe` | Masquerading | 7 instances from STUN.exe + explorer.exe; Trojan:Win32/PowerRunner.A |
| `pssdnsvc.exe` | Suspicious service | `C:\Windows\` — name/path mismatch for PsShutdown |
| `atmfd.dll` | Missing driver | In Autoruns but absent from filesystem |

### Attacker Activity

| Indicator | Detail |
|-----------|--------|
| Lateral movement | `net use H: \\172.16.6.12\c$\Users` — net.exe PID 9128 |
| Execution | STUN.exe as scheduled task → svchost.exe → taskhostw.exe |
| Evasion | msedge.exe masquerading; Defender detected + terminated repeatedly |

---

## Incident Timeline (UTC)

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2023-01-24 | Incident declared; F-Response agents deployed |
| 2023-01-25 14:52:04 | Lateral movement — `net use H: \\172.16.6.12\c$\Users` |
| 2023-01-25 14:56:42–15:04:43 | msedge.exe PIDs spawned |
| 2023-01-25 15:00:56 | msedge.exe PID 2524 active at memory capture time |
| 2023-01-29 12:23:16 | Kansa post-intrusion collection (Autorunsc timestamp) |

---

## Notes

- **Kansa Autorunsc CSVs** (`rd01/dc01/file01/hunt01`) are on the Windows forensic workstation at `G:\SRL_Evidence\kansa\kansa-post-intrusion\Output_20230129122316\Autorunsc\` — not on this SIFT instance.
- **MemProcFS** is not installed on this SIFT instance.
- **VSCMount** is Windows-only — do not use on SIFT.
- Timestamps: always report in UTC.
- Vol3 binary: `/opt/volatility3-2.20.0/vol.py` — NOT `/usr/local/bin/vol.py` (that is Vol2).

---

## SESSION LOG

### 2026-06-14 — Verisift parser build-out

**Environment corrections (this box differs from the doc paths above):**
- Vol3 actual binary: `/opt/volatility3/bin/vol` (the `/opt/volatility3-2.20.0/vol.py` path does NOT exist here).
- No YARA CLI binary — only `python3-yara` (4.5.0) + `libyara10`.
- Memory Baseliner not installed.
- No SRL/memory evidence present on this box — all `/cases/srl/` + `/cases/memory/` paths are template docs only.

**Test data acquired (in `test_data/`):**
- `evtx/` — sbousseaden/EVTX-ATTACK-SAMPLES, 278 files, 50 MB.
- `amcache/amcache.hve` — real Win10 hive (regipy validated fixture, 1367 entries).
- `mft/MFT_extracted.bin` — $MFT from a 10 MB NTFS image built with `mkntfs`, extracted via `icat`.
- `prefetch/NOTEPAD.EXE-07476F82.pf` — **synthetic** v30 (Win10) prefetch, 336 bytes, built byte-accurately from the libscca format spec by `analysis/make_test_prefetch.py`. Synthetic because no Windows evidence is on the box and DNS was too flaky to pull a real sample (real `.pf` in DFIRArtifactMuseum are inside `.7z`/`.rar`; lazy git blob-fetch kept failing). It is parsed by the REAL pyscca tool, so the parser path is genuine.

**Parser status (`parsers.py`) — ALL 4 DONE & VERIFIED:**
- `run_evtx`  — **DONE, verified** against 3 EVTX attack samples (logon 4624, process 4688, Sysmon EID 1). Per-record try/except + `errors='replace'` encoding.
- `run_amcache` — **DONE, verified** against real Amcache.hve. Returns 1367 entries (matches regipy's `expected_entries_count` exactly). sha1 normalized to 40 chars; registry_key reconstructed; `name_contains` filter works.
- `run_mft` — **DONE, verified** against real $MFT via MFTECmd. 18 records, time-window filter works. Note: MFTECmd CSV needs `utf-8-sig` (BOM on first header).
- `run_prefetch` — **DONE, verified** via `pyscca` (libscca, court-vetted; handles Win10/11 MAM). Parsed name=NOTEPAD.EXE, run_count=7, 2 last-run times (6 zero slots skipped), `executable` filter works. Tooling note: no PECmd on box; pyscca has NO `get_number_of_last_run_times` — probe `get_last_run_time(i)` positionally (8 slots max).
- `_extract_artifact` — implemented (TSK `fls -r -p` → inode → `icat`); used when evidence is a full image rather than a pre-extracted artifact.

**Full end-to-end self-correction test — PASSED:**
- `classify()`: execution[evtx_4688+amcache] → **confirmed, conf 1.0** (≥0.75 ✓); single-source → inferred/0.5; no-artifact → unsupported/dropped.
- `run_verification_loop()` iteration trace: iter 1 = 1 hallucination dropped + 1 weak inference; iter 2 = weak claim corroborated → confirmed, hallucination not re-proposed. This is the demo self-correction sequence.

**Status: 4 of 4 parsers DONE. Pipeline end-to-end CONFIRMED.**

**MCP server wiring — COMPLETE & INTEGRATION-TESTED:**
- `server.py` was already wired: `open_evidence`→EvidenceHandle, `parse_evtx`→run_evtx, `get_amcache`→run_amcache, `extract_mft_timeline`→run_mft, `analyze_prefetch`→run_prefetch. `audit.py` signatures match (`audit_log(tool,args,result_meta,duration)` / `new_run_id`).
- Smoke test: `import server` OK — FastMCP("verisift"), all 5 tools registered + callable.
- Server start: stdio transport stands up cleanly (rejects non-JSON-RPC input as expected — proves it initialized).
- Integration: `open_evidence(LM_WMI_4624_4688_TargetHost.evtx)` → metadata w/ `read_only:true` + sha256; `parse_evtx(channel='Security', event_ids=[4624,4688])` → **8 events**, full structured JSON.
- Audit trail: JSONL written to `exports/execution_log.jsonl` (run_id, seq, duration per call). Note: audit default path is `/cases/out/...`; set `VERISIFT_LOG` to route under the case dir.

### >>> READY TO RECORD <<<
All 4 parsers verified, end-to-end self-correction loop passing, MCP server wired + integration-tested. Demo can be recorded.
(Optional polish only: swap synthetic `.pf` for a real sample; run a full-disk-image pass exercising `_extract_artifact`.)

**Demo driver:** `demo_investigation.py` — self-contained, drives the real server.py
tools + verify loop. Corroboration is **COMPUTED, not asserted**, via
`parsers.correlate()` (case-insensitive basename match of live 4688 process names
against live amcache/mft/prefetch output).

Primary evidence = `Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx`
(REAL EVTX-ATTACK-SAMPLES capture: 4x 4624 logons + 1x 4688 process-create of
notepad.exe). Artifact provenance: EVTX real, AMCACHE real (regipy hive, contains
notepad.exe), PREFETCH synthetic (valid v30, parsed by real pyscca), MFT real (bare
$MFT, system metafiles only).

Final demo output (genuine, all matches computed):
- `[CONFIRMED] execution notepad.exe  conf=1.0  supports=['amcache','evtx_4688','prefetch']`
  — rests on TWO REAL artifacts (evtx_4688 + amcache) plus the synthetic prefetch.
- `[INFERRED]  logon Administrator    conf=0.5  supports=['evtx_4624']` — honest single-source.
- `[INJECTED-TEST] EVILCORP.EXE` (synthetic, no artifact) -> **dropped** by verifier.
- Iteration trace: iter1 = 1 dropped + 2 inferred; iter2 = 1 confirmed + 1 inferred.
- Audit log = 9 tool calls (open_evidence x4 incl. per-artifact re-open, parse_evtx,
  get_amcache=1367, extract_mft_timeline=18, analyze_prefetch=1).

`correlate()` positive path independently verified: `7z.exe`->amcache, `$Boot`->mft,
`NOTEPAD.EXE`->amcache+prefetch. NOTE: server holds ONE evidence handle — re-open per
artifact when correlating (driver does this; visible in the audit log).

**Video launch commands:**
- T1 (live audit trail): `export VERISIFT_LOG=/cases/verisift/exports/execution_log.jsonl; : > "$VERISIFT_LOG"; tail -f "$VERISIFT_LOG"`
- T2 (agent run): `VERISIFT_LOG=/cases/verisift/exports/execution_log.jsonl python3 /cases/verisift/demo_investigation.py`
