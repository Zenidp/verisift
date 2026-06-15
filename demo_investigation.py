#!/usr/bin/env python3
"""
demo_investigation.py — Scripted VeriSIFT investigation for the demo video.

Drives the REAL server.py MCP tools (open_evidence, parse_evtx, get_amcache,
extract_mft_timeline) and the verify.py self-correction loop end to end, on a
single evidence file, printing each stage for the camera. Every tool call is
recorded to the audit log (VERISIFT_LOG) — that streaming log is Terminal 1.

Run:
    VERISIFT_LOG=/cases/verisift/exports/execution_log.jsonl \
        python3 /cases/verisift/demo_investigation.py
"""
from __future__ import annotations
import sys

sys.path.insert(0, "/cases/verisift")

import ntpath

import server
from audit import new_run_id
from parsers import correlate
from verify import Finding, run_verification_loop, CORROBORATION

# Primary evidence: a REAL EVTX attack sample whose Security log records both
# 4624 logons and a 4688 process-create of notepad.exe — so the notepad
# execution claim is genuinely corroborated (real evtx_4688 + real amcache
# entry; the synthetic prefetch adds a third). Provenance per artifact:
#   EVTX     — REAL    (EVTX-ATTACK-SAMPLES, med0x2e NTLM2SelfRelay capture)
#   AMCACHE  — REAL    (regipy validated Win10 hive; contains notepad.exe)
#   PREFETCH — SYNTHETIC (byte-accurate v30 .pf we built; parsed by real pyscca)
#   MFT      — REAL    (bare NTFS $MFT; system metafiles only, no user exes)
EVTX = "/cases/verisift/test_data/evtx/Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx"
AMCACHE = "/cases/verisift/test_data/amcache/amcache.hve"
MFT = "/cases/verisift/test_data/mft/MFT_extracted.bin"
PREFETCH = "/cases/verisift/test_data/prefetch/NOTEPAD.EXE-07476F82.pf"


def rule(title: str) -> None:
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def main() -> None:
    new_run_id()

    rule("VeriSIFT — Autonomous Disk-Image Incident Response (typed MCP + verify loop)")
    print("Evidence:", EVTX)

    # ---- Stage 1: open evidence (read-only, hashed) -------------------------
    rule("STAGE 1 — open_evidence()  [read-only, fail-closed]")
    meta = server.open_evidence(EVTX)
    print(f"  read_only : {meta['read_only']}")
    print(f"  size      : {meta['size_bytes']:,} bytes")
    print(f"  sha256    : {meta['sha256']}")

    # ---- Stage 2: parse the Security log ------------------------------------
    rule("STAGE 2 — parse_evtx(channel='Security', event_ids=[4624, 4688])")
    out = server.parse_evtx(channel="Security", event_ids=[4624, 4688])
    logons = [e for e in out["events"] if e["event_id"] == 4624]
    procs = [e for e in out["events"] if e["event_id"] == 4688]
    print(f"  {out['count']} events  ->  {len(logons)} logons (4624) | {len(procs)} process-creates (4688)")
    if logons:
        d = logons[1]["data"] if len(logons) > 1 else logons[0]["data"]
        print(f"  e.g. logon: {d.get('TargetDomainName')}\\{d.get('TargetUserName')} "
              f"type {d.get('LogonType')} from {d.get('IpAddress')}")

    # ---- Stage 3: propose findings (grounded LIVE in parsed events) ---------
    rule("STAGE 3 — agent proposes structured findings (live from parsed events)")
    admin_logon = next((e for e in logons
                        if e["data"].get("TargetUserName") == "Administrator"), logons[0])
    target_user = admin_logon["data"].get("TargetUserName", "unknown")
    logon_time = admin_logon["time"]

    # Real process names extracted from the 4688 NewProcessName field.
    proc_names: list[str] = []
    for e in procs:
        full = e["data"].get("NewProcessName") or e["data"].get("ProcessName")
        if full:
            base = ntpath.basename(full)
            if base not in proc_names:
                proc_names.append(base)

    print(f"  logon     : {target_user}  (from 4624)")
    print(f"  execution : {proc_names}  (basenames from 4688 NewProcessName)")
    print(f"  [INJECTED-TEST] EVILCORP.EXE  — synthetic claim with NO artifact, "
          f"to demonstrate the drop (NOT a real finding)")

    # ---- Stage 4: verification loop with COMPUTED corroboration -------------
    rule("STAGE 4 — verification loop  [corroboration is COMPUTED via correlate()]")

    computed: dict[str, dict] = {}   # process -> {artifact: [matches]}

    def propose(iteration: int) -> list[Finding]:
        if iteration == 1:
            # First pass: only the originating source is known. Execution
            # claims are single-source; the injected test claim has nothing.
            out = [Finding(claim="logon", target=target_user, time=logon_time,
                           supports={"evtx_4624"})]
            for p in proc_names:
                out.append(Finding(claim="execution", target=p, time=logon_time,
                                   supports={"evtx_4688"}))
            out.append(Finding(claim="execution", target="[INJECTED-TEST] EVILCORP.EXE",
                               time=logon_time, supports={"unverified_rumor"}))
            return out

        # Second pass: actually RE-RUN the other parsers and correlate the
        # real process names against their real output. supports gains an
        # artifact ONLY when correlate() returns a genuine basename hit.
        # The server holds ONE evidence handle, so re-open per artifact.
        server.open_evidence(AMCACHE)
        am = server.get_amcache()                   # live amcache entries
        server.open_evidence(MFT)
        mf = server.extract_mft_timeline()          # live $MFT records
        server.open_evidence(PREFETCH)
        pf = server.analyze_prefetch()              # live prefetch entries
        server.open_evidence(EVTX)                  # restore primary handle

        out = [Finding(claim="logon", target=target_user, time=logon_time,
                       supports={"evtx_4624"})]
        for p in proc_names:
            hits = correlate(p, am["entries"], mf["records"], pf["executions"])
            computed[p] = hits
            supports = {"evtx_4688"} | set(hits.keys())
            out.append(Finding(claim="execution", target=p, time=logon_time,
                               supports=supports))
        # the injected test claim is NOT re-proposed (it was unsupported)
        return out

    def refine(kept: list[Finding], iteration: int) -> None:
        print(f"  refine(): {len(kept)} kept claims -> re-running amcache / mft / "
              f"prefetch and correlating real names")

    final, traces = run_verification_loop(propose, refine)

    print("\n  COMPUTED correlation (live basename match):")
    for p in proc_names:
        hits = computed.get(p, {})
        if hits:
            detail = "  ".join(f"{k}={v}" for k, v in hits.items())
            print(f"    {p:16} -> HIT in {detail}")
        else:
            print(f"    {p:16} -> no match in amcache / mft / prefetch  "
                  f"(artifacts are from other systems) -> stays single-source")

    print("\n  iteration trace:")
    for t in traces:
        print(f"    iter {t.iteration}:  confirmed={t.confirmed}  inferred={t.inferred}"
              f"  dropped={t.dropped}   | {t.note}")

    # ---- Stage 5: final report ----------------------------------------------
    rule("STAGE 5 — final report  [honest: only what the artifacts support]")
    for f in final:
        agree = sorted(f.supports & CORROBORATION.get(f.claim, set()))
        print(f"  [{f.status.upper():9}] {f.claim:9} {f.target:30} "
              f"conf={f.confidence:<4} supports={agree}")
    print(f"\n  injected test claim dropped: {sum(t.dropped for t in traces)}  "
          f"(EVILCORP.EXE — no corroborating artifact, caught by the verifier)")
    print("\n  Every artifact match above is COMPUTED by correlate() and every "
          "tool call is in the audit log (exports/execution_log.jsonl).")
    print("=" * 74)


if __name__ == "__main__":
    main()
