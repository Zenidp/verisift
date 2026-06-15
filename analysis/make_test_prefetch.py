#!/usr/bin/env python3
"""
make_test_prefetch.py — Build a minimal, byte-accurate Windows 10 (format
version 30, variant 1) prefetch (.pf) file from the documented libscca format.

Why synthetic: this SIFT box has no Windows evidence and DNS was too flaky to
pull a real .pf sample. The architect explicitly authorized building one from
spec. It is parsed by the REAL pyscca/libscca tool in run_prefetch, so this
exercises the actual court-vetted parser, not a hand-rolled reader.

Layout (little-endian), per libscca scca_file_header / scca_file_information_v30_1:
    header            : 84 bytes
    file information  : 220 bytes  (so metrics_array_offset = 84+220 = 0x130)
    --> total file    : 304 bytes, all array counts = 0 (nothing to cross-check)
"""
import struct
import sys
from datetime import datetime, timezone

EXE_NAME = "NOTEPAD.EXE"
RUN_COUNT = 7
# Two real last-run times; remaining 6 FILETIME slots left zero (unused).
LAST_RUN_TIMES = [
    datetime(2026, 6, 12, 9, 15, 30, tzinfo=timezone.utc),
    datetime(2026, 6, 13, 14, 42, 5, tzinfo=timezone.utc),
]

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def to_filetime(dt: datetime) -> int:
    delta = dt - _EPOCH_1601
    return int(delta.total_seconds() * 10_000_000)


def build() -> bytes:
    # ---- File information v30_1 (220 bytes), built first to know its size ----
    METRICS_OFFSET = 0x130          # 304 = 84 (header) + 220 (this section)
    fi = b""
    # libscca derives the metrics-array upper bound from the FIRST non-zero of
    # trace_chain / filename / volumes offsets, else file_size. Leave those
    # three at 0 (their counts/sizes are 0 anyway) so the bound becomes
    # file_size, and metrics_array_offset (0x130) sits validly below it.
    fi += struct.pack("<I", METRICS_OFFSET)  # metrics_array_offset
    fi += struct.pack("<I", 1)               # number_of_file_metrics_entries
    fi += struct.pack("<I", 0)               # trace_chain_array_offset
    fi += struct.pack("<I", 0)               # number_of_trace_chain_entries
    fi += struct.pack("<I", 0)               # filename_strings_offset
    fi += struct.pack("<I", 0)               # filename_strings_size
    fi += struct.pack("<I", 0)               # volumes_information_offset
    fi += struct.pack("<I", 0)               # number_of_volumes
    fi += struct.pack("<I", 0)               # volumes_information_size
    fi += b"\x00" * 8                        # unknown3c

    # last_run_time: 8 FILETIME slots (64 bytes)
    runtimes = b""
    for i in range(8):
        if i < len(LAST_RUN_TIMES):
            runtimes += struct.pack("<Q", to_filetime(LAST_RUN_TIMES[i]))
        else:
            runtimes += struct.pack("<Q", 0)
    fi += runtimes

    fi += b"\x00" * 16                        # unknown4
    fi += struct.pack("<I", RUN_COUNT)        # run_count
    fi += b"\x00" * 4                          # unknown5a
    fi += b"\x00" * 4                          # unknown5b
    fi += struct.pack("<I", 0)                # hash_string_offset
    fi += struct.pack("<I", 0)                # hash_string_size
    fi += b"\x00" * 76                         # unknown6
    assert len(fi) == 220, f"file-info size {len(fi)} != 220"

    # One zeroed 32-byte v23/v30 file-metrics entry lives at METRICS_OFFSET
    # (libscca rejects a 0-entry metrics array). All fields zero is accepted:
    # read_data copies the entry without dereferencing the filename strings.
    padding = b"\x00" * 32
    total_size = 84 + len(fi) + len(padding)

    # ---- Header (84 bytes) ----
    hdr = b""
    hdr += struct.pack("<I", 30)               # format_version = 30 (Win10)
    hdr += b"SCCA"                              # signature
    hdr += struct.pack("<I", 17)               # unknown1 (typical 0x11)
    hdr += struct.pack("<I", total_size)       # file_size
    exe_utf16 = (EXE_NAME + "\x00").encode("utf-16-le")
    exe_field = exe_utf16 + b"\x00" * (60 - len(exe_utf16))
    hdr += exe_field[:60]                       # executable_filename (60)
    hdr += struct.pack("<I", 0x07476F82)       # prefetch_hash
    hdr += struct.pack("<I", 0)                # unknown2
    assert len(hdr) == 84, f"header size {len(hdr)} != 84"

    return hdr + fi + padding


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "NOTEPAD.EXE-07476F82.pf"
    data = build()
    with open(out, "wb") as f:
        f.write(data)
    print(f"wrote {out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
