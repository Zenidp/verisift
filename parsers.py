"""
parsers.py — Thin wrappers around real SIFT DFIR tools.

THIS IS THE ONLY FILE YOU NEED TO FILL IN ON THE SIFT WORKSTATION.
Each function:
    1. Mounts/extracts the needed artifact from the read-only image.
    2. Runs the real tool via subprocess (read-only args only).
    3. Parses raw output into structured dicts.

The subprocess calls are CONSTRAINED here — the agent never composes them.
Only these specific, reviewed command shapes can ever run. That is what keeps
the guardrail architectural.

Tool suggestions (all ship on / installable in SIFT):
    $MFT       -> analyzeMFT.py  OR  MFTECmd (via mono/dotnet)  OR  mft_dump
    prefetch   -> PECmd          OR  prefetchruncounts / windowsprefetch (pip)
    amcache    -> regipy (amcache_parser)  OR  AmcacheParser
    evtx       -> evtx_dump (Rust) OR python-evtx (Evtx)  -> then filter IDs

Replace each `raise NotImplementedError` with real extraction + parsing.
Keep the RETURN SHAPE identical so verify.py keeps working unchanged.
"""

from __future__ import annotations
import subprocess
from evidence import EvidenceHandle


def _extract_artifact(ev: EvidenceHandle, fs_path: str, out_path: str) -> str:
    """Pull a single file out of the image WITHOUT mounting writable.

    Recommended: `icat`/`fls` from The Sleuth Kit (read-only by nature), or
    loop-mount with `mount -o ro,loop,noload`. Returns local path to artifact.
    """
    # Example TSK shape (fill in real inode resolution):
    #   fls -r -p <image> | grep <fs_path>   -> get inode
    #   icat <image> <inode> > out_path
    raise NotImplementedError("Wire up TSK icat/fls extraction here.")


def run_mft(ev: EvidenceHandle, start_iso, end_iso) -> list[dict]:
    """Return MFT records as:
       [{"path","created","modified","accessed","mft_entry","size"}]"""
    # mft = _extract_artifact(ev, "/$MFT", "/tmp/mft.bin")
    # raw = subprocess.run(["analyzeMFT.py","-f",mft,"--csv","-o","-"],
    #                      capture_output=True, text=True, check=True).stdout
    # parse CSV -> dicts, filter by [start_iso, end_iso]
    raise NotImplementedError("Parse $MFT into structured records.")


def run_prefetch(ev: EvidenceHandle, executable) -> list[dict]:
    """Return:
       [{"name","run_count","last_run_times":[...],"source_pf"}]"""
    raise NotImplementedError("Parse prefetch .pf into structured records.")


def run_amcache(ev: EvidenceHandle, name_contains) -> list[dict]:
    """Return:
       [{"name","sha1","first_seen","path","registry_key"}]"""
    raise NotImplementedError("Parse Amcache.hve into structured records.")


def run_evtx(ev: EvidenceHandle, channel, event_ids) -> list[dict]:
    """Return:
       [{"event_id","time","computer","data","record_id","channel"}]"""
    raise NotImplementedError("Parse EVTX into structured records.")
