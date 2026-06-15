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
import ntpath
import subprocess
from evidence import EvidenceHandle


def correlate(name: str,
              amcache_entries: list[dict] | None = None,
              mft_records: list[dict] | None = None,
              prefetch_entries: list[dict] | None = None) -> dict[str, list[str]]:
    """Compute REAL cross-artifact corroboration for an executable name.

    Given a process/file name (e.g. "calc.exe") and the live outputs of the
    other parsers, return which artifacts actually contain that name and the
    matching value(s). Matching is case-insensitive on the file BASENAME, so
    a full-path field ("C:\\Windows\\System32\\calc.exe") still matches.

    Returns e.g. {"amcache": ["calc.exe"], "mft": ["CALC.EXE"]}. An artifact
    only appears if there is a genuine hit — nothing is asserted. The caller
    adds those artifact keys to a Finding's `supports`, turning corroboration
    into something COMPUTED, not hand-wired.
    """
    target = ntpath.basename(name).lower()
    hits: dict[str, list[str]] = {}

    def _scan(artifact: str, values):
        found = []
        for v in values:
            if not v:
                continue
            if ntpath.basename(str(v)).lower() == target:
                found.append(str(v))
        if found:
            hits[artifact] = sorted(set(found))

    if amcache_entries:
        vals = []
        for e in amcache_entries:
            vals.append(e.get("name"))
            vals.append(e.get("path"))
        _scan("amcache", vals)

    if mft_records:
        _scan("mft", [r.get("path") for r in mft_records])

    if prefetch_entries:
        _scan("prefetch", [p.get("name") for p in prefetch_entries])

    return hits


def _extract_artifact(ev: EvidenceHandle, fs_path: str, out_path: str) -> str:
    """Pull a single file out of the image WITHOUT mounting writable.

    Recommended: `icat`/`fls` from The Sleuth Kit (read-only by nature), or
    loop-mount with `mount -o ro,loop,noload`. Returns local path to artifact.
    """
    # Resolve the inode for fs_path via TSK `fls -r -p`, then `icat` it out.
    # Both tools are read-only by nature — they never open the image writable.
    import re

    target = fs_path.lstrip("/").replace("\\", "/").lower()
    listing = subprocess.run(
        ["fls", "-r", "-p", ev.path],
        capture_output=True, text=True, check=True,
    ).stdout

    inode = None
    for line in listing.splitlines():
        # Format: "r/r 64-128-1:\tWindows/System32/file.ext"
        m = re.match(r"^[^ ]+\s+([0-9]+)-[0-9]+-[0-9]+:\s+(.*)$", line)
        if not m:
            continue
        ino, path = m.group(1), m.group(2).replace("\\", "/").lower()
        if path == target or path.endswith("/" + target):
            inode = ino
            break

    if inode is None:
        raise FileNotFoundError(f"{fs_path} not found in image {ev.path}")

    with open(out_path, "wb") as fh:
        subprocess.run(["icat", ev.path, inode], stdout=fh, check=True)
    return out_path


def run_mft(ev: EvidenceHandle, start_iso=None, end_iso=None) -> list[dict]:
    """Return MFT records as:
       [{"path","created","modified","accessed","mft_entry","size"}]

    ev.path points at an extracted $MFT file (use _extract_artifact first if
    you only have a disk image). Parsed with MFTECmd (EZ Tools / dotnet).

    start_iso / end_iso: optional ISO-8601 bounds. If set, a record is kept
    when its created OR modified time falls inside [start_iso, end_iso].
    """
    import csv
    import os
    import tempfile
    from datetime import datetime

    def _parse_ts(val: str):
        if not val:
            return None
        s = val.strip().replace("T", " ").replace("Z", "")
        # MFTECmd emits sub-second precision beyond microseconds; trim to 6.
        if "." in s:
            head, frac = s.split(".", 1)
            frac = "".join(c for c in frac if c.isdigit())[:6]
            s = f"{head}.{frac}" if frac else head
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None

    lo = _parse_ts(start_iso) if start_iso else None
    hi = _parse_ts(end_iso) if end_iso else None

    outdir = tempfile.mkdtemp(prefix="mftecmd_")
    csv_path = os.path.join(outdir, "mft.csv")
    subprocess.run(
        ["dotnet", "/opt/zimmermantools/MFTECmd.dll",
         "-f", ev.path, "--csv", outdir, "--csvf", "mft.csv"],
        capture_output=True, text=True, check=True,
    )

    results: list[dict] = []
    # utf-8-sig strips the BOM MFTECmd writes on the first column header.
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                parent = (row.get("ParentPath") or "").rstrip("\\")
                fname = row.get("FileName") or ""
                path = f"{parent}\\{fname}" if parent else fname

                created = row.get("Created0x10") or ""
                modified = row.get("LastModified0x10") or ""
                accessed = row.get("LastAccess0x10") or ""

                if lo or hi:
                    cands = [t for t in (_parse_ts(created), _parse_ts(modified)) if t]
                    in_window = any(
                        (lo is None or t >= lo) and (hi is None or t <= hi)
                        for t in cands
                    )
                    if cands and not in_window:
                        continue

                entry_raw = row.get("EntryNumber")
                size_raw = row.get("FileSize")

                results.append({
                    "path":      path,
                    "created":   created,
                    "modified":  modified,
                    "accessed":  accessed,
                    "mft_entry": int(entry_raw) if (entry_raw or "").isdigit() else entry_raw,
                    "size":      int(size_raw) if (size_raw or "").isdigit() else 0,
                })
            except Exception:
                # One malformed row never aborts the parse.
                continue

    return results


def run_prefetch(ev: EvidenceHandle, executable=None) -> list[dict]:
    """Return:
       [{"name","run_count","last_run_times","source_pf"}]

    ev.path points at a single .pf file (compressed Win10/11 MAM or raw SCCA).
    Parsed with pyscca (libyal libscca) — the court-vetted parser that handles
    every format version incl. Win10/11 MAM decompression.

    executable: optional case-insensitive substring filter on the executable
    name. Returns [] if the .pf doesn't match.
    """
    import os
    import pyscca

    source_pf = os.path.basename(ev.path)
    results: list[dict] = []

    scca = pyscca.file()
    try:
        scca.open(ev.path)
        try:
            name = scca.get_executable_filename() or ""

            if executable and executable.lower() not in name.lower():
                return []

            run_count = scca.get_run_count()

            # pyscca exposes last-run times only positionally (no count getter).
            # v17 has 1 slot, v23+/v30/v31 have up to 8. Probe each slot,
            # stopping at the first out-of-range index; skip unused/zero slots.
            last_run_times: list[str] = []
            for i in range(8):
                try:
                    ts = scca.get_last_run_time(i)
                except Exception:
                    break
                # libscca returns None / epoch-zero for unused slots — skip them.
                if ts is None:
                    continue
                if getattr(ts, "year", 0) <= 1601:
                    continue
                last_run_times.append(ts.isoformat())

            results.append({
                "name":           name,
                "run_count":      run_count,
                "last_run_times": last_run_times,
                "source_pf":      source_pf,
            })
        except Exception:
            # Malformed file content — return what we have, never abort hard.
            pass
    finally:
        try:
            scca.close()
        except Exception:
            pass

    return results


def run_amcache(ev: EvidenceHandle, name_contains=None) -> list[dict]:
    """Return:
       [{"name","sha1","first_seen","path","registry_key"}]

    ev.path points at an extracted Amcache.hve. Parsed with regipy's
    RegistryHive reader; we reuse regipy's own numeric field map so behaviour
    tracks the validated AmCachePlugin, but we additionally reconstruct the
    source registry key path for each entry.

    name_contains: optional case-insensitive substring filter on name/path.
    """
    import ntpath
    from regipy.registry import RegistryHive
    from regipy.exceptions import RegistryKeyNotFoundException
    from regipy.plugins.amcache.amcache import AMCACHE_FIELD_NUMERIC_MAPPINGS
    from regipy.utils import convert_wintime

    hive = RegistryHive(ev.path)
    needle = name_contains.lower() if name_contains else None
    results: list[dict] = []

    def _emit(values: dict, key_path: str, key_wintime: int):
        try:
            # Translate legacy numeric value names -> human field names.
            entry = dict(values)
            for num, human in AMCACHE_FIELD_NUMERIC_MAPPINGS.items():
                if num in entry:
                    entry[human] = entry.pop(num)

            path = (entry.get("full_path")
                    or entry.get("lower_case_long_path")
                    or entry.get("low_case_long_path")
                    or entry.get("long_path_hash")
                    or "")
            name = entry.get("name") or (ntpath.basename(path) if path else "")

            sha1 = entry.get("sha1") or entry.get("file_id") or ""
            # regipy strips a 4-char zero prefix; mirror that when present.
            if sha1 and len(sha1) > 40:
                sha1 = sha1[-40:]

            # first_seen: prefer the file's recorded creation, else the
            # Amcache key's own last-write time (when the entry appeared).
            created = entry.get("created_timestamp")
            if created:
                first_seen = convert_wintime(created, as_json=True) if isinstance(created, int) else created
            else:
                first_seen = convert_wintime(key_wintime, as_json=True)

            if needle and needle not in name.lower() and needle not in path.lower():
                return

            results.append({
                "name":         name,
                "sha1":         sha1,
                "first_seen":   first_seen,
                "path":         path,
                "registry_key": key_path,
            })
        except Exception:
            # Skip a malformed entry without aborting the whole hive parse.
            return

    # Legacy format: \Root\File\<volume>\<entry>
    try:
        file_key = hive.get_key(r"\Root\File")
        for vol in file_key.iter_subkeys():
            for fe in vol.iter_subkeys():
                vals = {v.name: v.value for v in fe.iter_values(as_json=True)}
                _emit(vals, rf"\Root\File\{vol.name}\{fe.name}", fe.header.last_modified)
    except RegistryKeyNotFoundException:
        pass

    # Modern format (Win10+): \Root\InventoryApplicationFile\<entry>
    try:
        inv_key = hive.get_key(r"\Root\InventoryApplicationFile")
        for fe in inv_key.iter_subkeys():
            vals = {v.name: v.value for v in fe.iter_values(as_json=True)}
            _emit(vals, rf"\Root\InventoryApplicationFile\{fe.name}", fe.header.last_modified)
    except RegistryKeyNotFoundException:
        pass

    return results


def run_evtx(ev: EvidenceHandle, channel, event_ids) -> list[dict]:
    """Return:
       [{"event_id","time","computer","data","record_id","channel"}]

    ev.path must point to a readable .evtx file (direct artifact, not a disk
    image — extraction from an image is done by the caller via _extract_artifact
    before handing the result to this function).

    channel: str or None — if set, only records whose System/Channel matches
             are returned.  Pass None to return all channels.
    event_ids: list[int] or None — if set, only those Event IDs are returned.
    """
    import Evtx.Evtx as evtx_lib
    import xml.etree.ElementTree as ET

    NS = "http://schemas.microsoft.com/win/2004/08/events/event"
    target_ids = set(int(x) for x in event_ids) if event_ids else set()

    results: list[dict] = []

    try:
        with evtx_lib.Evtx(ev.path) as log:
            for record in log.records():
                try:
                    xml_bytes = record.xml().encode("utf-8", errors="replace")
                    root = ET.fromstring(xml_bytes)

                    sys_el = root.find(f"{{{NS}}}System")
                    if sys_el is None:
                        continue

                    def _text(tag: str) -> str:
                        el = sys_el.find(f"{{{NS}}}{tag}")
                        return (el.text or "") if el is not None else ""

                    eid_raw = _text("EventID")
                    eid = int(eid_raw) if eid_raw.isdigit() else None
                    chan = _text("Channel")
                    time_el = sys_el.find(f"{{{NS}}}TimeCreated")
                    time_str = time_el.get("SystemTime", "") if time_el is not None else ""
                    computer = _text("Computer")
                    recid_raw = _text("EventRecordID")
                    record_id = int(recid_raw) if recid_raw.isdigit() else None

                    if target_ids and eid not in target_ids:
                        continue
                    if channel and chan != channel:
                        continue

                    data: dict = {}
                    for container_tag in ("EventData", "UserData"):
                        container = root.find(f"{{{NS}}}{container_tag}")
                        if container is None:
                            continue
                        for el in container.iter():
                            name = el.get("Name") or el.tag.split("}")[-1]
                            if el.text:
                                safe = el.text.encode(
                                    "utf-8", errors="replace"
                                ).decode("utf-8")
                                data[name] = safe

                    results.append({
                        "event_id":  eid,
                        "time":      time_str,
                        "computer":  computer,
                        "data":      data,
                        "record_id": record_id,
                        "channel":   chan,
                    })

                except Exception:
                    # Skip corrupt / unparseable records — don't abort the run.
                    continue

    except Exception as exc:
        raise RuntimeError(f"Failed to open EVTX {ev.path}: {exc}") from exc

    return results
