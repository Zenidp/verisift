#!/usr/bin/env python3
"""
make_diagram.py — Generate the VeriSIFT architecture diagram.

Outputs:
    docs/architecture.svg    (primary — upload to Devpost)
    docs/architecture.png    (fallback — via graphviz render)

Run:  python3 analysis/make_diagram.py
"""

import os
import subprocess
import textwrap

# Output goes to docs/ (tracked in repo, never in evidence dirs)
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "docs")
os.makedirs(OUT_DIR, exist_ok=True)
DOT_PATH = os.path.join(OUT_DIR, "architecture.dot")
SVG_PATH = os.path.join(OUT_DIR, "architecture.svg")
PNG_PATH = os.path.join(OUT_DIR, "architecture.png")

DOT_SRC = textwrap.dedent(r"""
digraph verisift {
    // ── global ────────────────────────────────────────────────────────
    graph [
        label      = "VeriSIFT — Architecture\nTyped MCP Server (#2)  ⊕  Persistent Self-Correction Loop (#7)"
        labelloc   = "t"
        fontname   = "Helvetica Neue,Helvetica,Arial,sans-serif"
        fontsize   = 18
        fontcolor  = "#1a1a2e"
        bgcolor    = "#f8f9ff"
        rankdir    = LR
        splines    = ortho
        nodesep    = 0.7
        ranksep    = 1.1
        pad        = 0.6
        margin     = 0.5
    ]
    node [fontname="Helvetica Neue,Helvetica,Arial,sans-serif" fontsize=12 style="filled,rounded" penwidth=1.5]
    edge [fontname="Helvetica Neue,Helvetica,Arial,sans-serif" fontsize=10 penwidth=1.5]

    // ── CLUSTER: AI layer ─────────────────────────────────────────────
    subgraph cluster_agent {
        label      = "AI Layer"
        fontsize   = 13
        fontcolor  = "#2d3561"
        style      = "rounded,dashed"
        color      = "#2d3561"
        bgcolor    = "#eef0fb"

        agent [
            label     = "<<b>AI Agent</b>>\n(Claude Code)"
            shape     = box
            fillcolor = "#2d3561"
            fontcolor = white
            color     = "#1a1a2e"
        ]

        verify [
            label     = "<<b>verify.py</b>>\n──────────────\nclassify(finding)\nrun_verification_loop()\nMAX_ITERATIONS = 4\n──────────────\n  0 artifacts → DROPPED\n  1 artifact  → inferred\n≥2 artifacts → confirmed"
            shape     = box
            fillcolor = "#c94b4b"
            fontcolor = white
            color     = "#8b0000"
        ]

        audit [
            label     = "<<b>audit.py</b>>\n──────────\nJSONL per tool call\nrun_id · seq · ts (UTC)\ntool · args · result_meta\nduration_s"
            shape     = box
            fillcolor = "#4b6cb7"
            fontcolor = white
            color     = "#2d3561"
        ]

        correlate [
            label     = "<<b>correlate()</b>>\n──────────────\nBasename-match:\nEVTX name → amcache\n          → prefetch\n          → mft\nComputed, NOT asserted"
            shape     = box
            fillcolor = "#c94b4b"
            fontcolor = white
            color     = "#8b0000"
        ]
    }

    // ── CLUSTER: MCP Server (trust boundary) ──────────────────────────
    subgraph cluster_mcp {
        label      = "VeriSIFT MCP Server  ·  server.py"
        fontsize   = 13
        fontcolor  = "#145a32"
        style      = "rounded"
        color      = "#145a32"
        bgcolor    = "#eafaf1"
        penwidth   = 2.5

        open_ev [
            label     = "open_evidence(path)\n─────────────────\nreturns EvidenceHandle\nread_only: true\nsha256 at open"
            shape     = box
            fillcolor = "#1e8449"
            fontcolor = white
            color     = "#145a32"
        ]
        parse_evtx [
            label     = "parse_evtx()\nchannel · event_ids"
            shape     = box
            fillcolor = "#27ae60"
            fontcolor = white
            color     = "#145a32"
        ]
        get_amcache [
            label     = "get_amcache()\nname_contains?"
            shape     = box
            fillcolor = "#27ae60"
            fontcolor = white
            color     = "#145a32"
        ]
        extract_mft [
            label     = "extract_mft_timeline()\nstart? · end?"
            shape     = box
            fillcolor = "#27ae60"
            fontcolor = white
            color     = "#145a32"
        ]
        analyze_pf [
            label     = "analyze_prefetch()\nexecutable?"
            shape     = box
            fillcolor = "#27ae60"
            fontcolor = white
            color     = "#145a32"
        ]
    }

    // ── CLUSTER: guardrail ─────────────────────────────────────────────
    subgraph cluster_guardrail {
        label      = "Evidence Guardrail  ·  evidence.py"
        fontsize   = 13
        fontcolor  = "#7d3c00"
        style      = "rounded"
        color      = "#e67e22"
        bgcolor    = "#fef9e7"
        penwidth   = 2.5

        evidence [
            label     = "<<b>EvidenceHandle</b>>\n─────────────────────────────\nos.open(path, O_RDONLY)\nstat check: S_IWUSR|S_IWGRP|S_IWOTH\n→ FAIL CLOSED if any write bit set\nReadOnlyViolation raised\n─────────────────────────────\nSHA-256 at open\nSHA-256 on reverify_integrity()\n─────────────────────────────\n⛔ No write path exists in code"
            shape     = box
            fillcolor = "#e67e22"
            fontcolor = white
            color     = "#7d3c00"
            penwidth  = 2
        ]
    }

    // ── CLUSTER: parsers ───────────────────────────────────────────────
    subgraph cluster_parsers {
        label      = "Parsers  ·  parsers.py"
        fontsize   = 13
        fontcolor  = "#1a1a2e"
        style      = "rounded,dashed"
        color      = "#555"
        bgcolor    = "#f0f0f0"

        p_evtx [
            label     = "run_evtx()\npython-evtx 0.8.1\n→ {event_id,time,data,…}"
            shape     = box
            fillcolor = "#888"
            fontcolor = white
            color     = "#444"
        ]
        p_am [
            label     = "run_amcache()\nregipy 6.2.1\n→ {name,sha1,first_seen,path}"
            shape     = box
            fillcolor = "#888"
            fontcolor = white
            color     = "#444"
        ]
        p_mft [
            label     = "run_mft()\nMFTECmd 1.3.0.0\n→ {path,created,modified,…}"
            shape     = box
            fillcolor = "#888"
            fontcolor = white
            color     = "#444"
        ]
        p_pf [
            label     = "run_prefetch()\npyscca/libscca 20250915\n→ {name,run_count,last_run_times}"
            shape     = box
            fillcolor = "#888"
            fontcolor = white
            color     = "#444"
        ]
    }

    // ── CLUSTER: findings / output ─────────────────────────────────────
    subgraph cluster_output {
        label      = "Final Report"
        fontsize   = 13
        fontcolor  = "#1a1a2e"
        style      = "rounded,dashed"
        color      = "#2d3561"
        bgcolor    = "#eef0fb"

        confirmed [
            label     = "✅ CONFIRMED\nconf ≥ 0.75\n≥2 artifacts agree"
            shape     = box
            fillcolor = "#1e8449"
            fontcolor = white
            color     = "#145a32"
        ]
        inferred [
            label     = "⚠️ INFERRED\nconf = 0.5\nsingle-source"
            shape     = box
            fillcolor = "#d4ac0d"
            fontcolor = white
            color     = "#9a7d0a"
        ]
        dropped [
            label     = "🚫 DROPPED\nconf = 0.0\nno artifact support\n(hallucination caught)"
            shape     = box
            fillcolor = "#c0392b"
            fontcolor = white
            color     = "#7b241c"
        ]
    }

    // ── FLOW EDGES ─────────────────────────────────────────────────────

    // agent → MCP tools
    agent -> open_ev   [label=" typed tool calls\n(no execute_shell)" color="#2d3561" fontcolor="#2d3561"]
    agent -> parse_evtx [color="#2d3561" style=dashed]
    agent -> get_amcache [color="#2d3561" style=dashed]
    agent -> extract_mft [color="#2d3561" style=dashed]
    agent -> analyze_pf [color="#2d3561" style=dashed]

    // MCP tools → evidence handle
    open_ev -> evidence [label=" EvidenceHandle\n(O_RDONLY)" color="#e67e22" fontcolor="#7d3c00"]
    parse_evtx -> evidence [color="#e67e22" style=dashed]
    get_amcache -> evidence [color="#e67e22" style=dashed]
    extract_mft -> evidence [color="#e67e22" style=dashed]
    analyze_pf -> evidence [color="#e67e22" style=dashed]

    // evidence → parsers
    evidence -> p_evtx [color="#555"]
    evidence -> p_am   [color="#555"]
    evidence -> p_mft  [color="#555"]
    evidence -> p_pf   [color="#555"]

    // parsers → structured JSON back to agent
    p_evtx -> agent [label=" structured JSON\n(no raw bytes)" color="#2d3561" fontcolor="#2d3561" style=dashed]
    p_am   -> agent [color="#2d3561" style=dashed]
    p_mft  -> agent [color="#2d3561" style=dashed]
    p_pf   -> agent [color="#2d3561" style=dashed]

    // agent → verify loop
    agent -> verify [label=" proposes\n findings" color="#c94b4b" fontcolor="#8b0000"]

    // verify ↔ correlate
    verify -> correlate [label=" re-run +\n correlate" color="#c94b4b" fontcolor="#8b0000"]
    correlate -> verify [label=" hits dict" color="#c94b4b" fontcolor="#8b0000" style=dashed]

    // verify → outcomes
    verify -> confirmed [color="#1e8449"]
    verify -> inferred  [color="#d4ac0d"]
    verify -> dropped   [color="#c0392b"]

    // audit log (everything)
    open_ev -> audit    [color="#4b6cb7" style=dotted label=" seq++"]
    parse_evtx -> audit [color="#4b6cb7" style=dotted]
    get_amcache -> audit [color="#4b6cb7" style=dotted]
    extract_mft -> audit [color="#4b6cb7" style=dotted]
    analyze_pf -> audit  [color="#4b6cb7" style=dotted]

    // layout hints
    { rank=same; parse_evtx; get_amcache; extract_mft; analyze_pf }
    { rank=same; p_evtx; p_am; p_mft; p_pf }
    { rank=same; confirmed; inferred; dropped }
}
""")

with open(DOT_PATH, "w") as f:
    f.write(DOT_SRC)
print(f"wrote {DOT_PATH}")

for fmt, path in [("svg", SVG_PATH), ("png", PNG_PATH)]:
    result = subprocess.run(
        ["dot", f"-T{fmt}", DOT_PATH, "-o", path],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        size = os.path.getsize(path)
        print(f"✓ {path}  ({size:,} bytes)")
    else:
        print(f"✗ {fmt} failed: {result.stderr[:200]}")
