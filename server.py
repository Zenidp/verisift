"""
VeriSIFT MCP Server
===================
A purpose-built MCP server for autonomous disk-image incident response.

DESIGN PRINCIPLE (architectural guardrail, NOT prompt-based):
    The agent can ONLY call the typed functions registered below.
    There is NO execute_shell / run_command tool. Destructive operations
    are impossible because the capability does not exist in the server.

Every tool:
    1. Opens evidence READ-ONLY (enforced in evidence.py).
    2. Runs a specific DFIR parser as a child process.
    3. Parses raw output into structured JSON BEFORE returning to the LLM
       (prevents context-window overload + makes output verifiable).
    4. Emits a structured execution-log record (audit trail).

Run inside the SIFT Workstation after the DFIR tools are on PATH.
"""

from __future__ import annotations
import json
import time
from typing import Any

# MCP Python SDK  ->  pip install mcp
from mcp.server.fastmcp import FastMCP

from evidence import EvidenceHandle, ReadOnlyViolation
from audit import audit_log, new_run_id
from parsers import (
    run_mft,
    run_prefetch,
    run_amcache,
    run_evtx,
)

mcp = FastMCP("verisift")

# A single evidence handle is opened per session. Path is supplied once,
# read-only, and reused. The agent never passes arbitrary shell strings.
_EVIDENCE: EvidenceHandle | None = None


@mcp.tool()
def open_evidence(image_path: str) -> dict[str, Any]:
    """Open a disk image read-only for analysis.

    Args:
        image_path: Absolute path to the disk image (e.g. /cases/case01.E01).
    Returns:
        Metadata about the opened image (size, type, hash) — NO raw bytes.
    """
    global _EVIDENCE
    _EVIDENCE = EvidenceHandle.open(image_path)  # raises if not read-only-safe
    meta = _EVIDENCE.metadata()
    audit_log("open_evidence", {"image_path": image_path}, meta)
    return meta


def _require_evidence() -> EvidenceHandle:
    if _EVIDENCE is None:
        raise RuntimeError("Call open_evidence() before any analysis tool.")
    return _EVIDENCE


@mcp.tool()
def extract_mft_timeline(start_iso: str | None = None,
                         end_iso: str | None = None) -> dict[str, Any]:
    """Parse $MFT into a structured file-system timeline.

    Args:
        start_iso / end_iso: optional ISO-8601 window to bound results.
    Returns:
        {"records": [{"path", "created", "modified", "mft_entry", ...}], ...}
        Each record is traceable to an $MFT entry number (audit trail).
    """
    ev = _require_evidence()
    t0 = time.time()
    records = run_mft(ev, start_iso, end_iso)        # -> already structured
    out = {"tool": "extract_mft_timeline",
           "count": len(records),
           "records": records}
    audit_log("extract_mft_timeline",
              {"start": start_iso, "end": end_iso},
              {"count": len(records)}, duration=time.time() - t0)
    return out


@mcp.tool()
def analyze_prefetch(executable: str | None = None) -> dict[str, Any]:
    """Parse Windows Prefetch (.pf) for execution evidence.

    Args:
        executable: optional filter, e.g. "POWERSHELL.EXE".
    Returns:
        {"executions": [{"name", "run_count", "last_run_times", "source_pf"}]}
    """
    ev = _require_evidence()
    t0 = time.time()
    executions = run_prefetch(ev, executable)
    audit_log("analyze_prefetch", {"executable": executable},
              {"count": len(executions)}, duration=time.time() - t0)
    return {"tool": "analyze_prefetch",
            "count": len(executions),
            "executions": executions}


@mcp.tool()
def get_amcache(name_contains: str | None = None) -> dict[str, Any]:
    """Parse Amcache.hve for program presence/installation evidence.

    Returns entries traceable to registry keys (audit trail).
    """
    ev = _require_evidence()
    t0 = time.time()
    entries = run_amcache(ev, name_contains)
    audit_log("get_amcache", {"name_contains": name_contains},
              {"count": len(entries)}, duration=time.time() - t0)
    return {"tool": "get_amcache", "count": len(entries), "entries": entries}


@mcp.tool()
def parse_evtx(channel: str = "Security",
               event_ids: list[int] | None = None) -> dict[str, Any]:
    """Parse a Windows Event Log channel into structured events.

    Args:
        channel: e.g. "Security", "System".
        event_ids: optional filter, e.g. [4688, 4624].
    Returns:
        {"events": [{"event_id", "time", "computer", "data", "record_id"}]}
    """
    ev = _require_evidence()
    t0 = time.time()
    events = run_evtx(ev, channel, event_ids)
    audit_log("parse_evtx", {"channel": channel, "event_ids": event_ids},
              {"count": len(events)}, duration=time.time() - t0)
    return {"tool": "parse_evtx", "count": len(events), "events": events}


if __name__ == "__main__":
    mcp.run()
