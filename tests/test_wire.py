#!/usr/bin/env python3
"""An independent wire-format oracle using Python struct and zlib CRC-32."""

import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import zlib


BINARY = Path(sys.argv[1]).resolve()
CHECKS = 0


def require(condition, description):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(description)


def run(*args, expected=0):
    result = subprocess.run(
        [str(BINARY), *map(str, args)], capture_output=True, timeout=10, check=False
    )
    require(
        result.returncode == expected,
        f"{args}: expected {expected}, got {result.returncode}: {result.stderr!r}",
    )
    return result


def record(sequence, payload):
    metadata = struct.pack("<4sIQI", b"CLG1", 1, sequence, len(payload))
    checksum = zlib.crc32(metadata + payload)
    return metadata + struct.pack("<I", checksum) + payload + struct.pack(
        "<4sIQ", b"DONE", len(payload), sequence
    )


def inspect(path, state, records, valid_bytes, problem=None):
    result = run("inspect", path, expected=0 if state == "clean" else 2)
    fields = dict(field.split("=", 1) for field in result.stdout.decode().split())
    require(fields["state"] == state, fields)
    require(int(fields["records"]) == records, fields)
    require(int(fields["valid_bytes"]) == valid_bytes, fields)
    require(int(fields["file_bytes"]) == path.stat().st_size, fields)
    if problem is not None:
        require(fields["problem"] == problem, fields)


def main():
    require(zlib.crc32(b"123456789") == 0xCBF43926, "CRC oracle known vector")
    with tempfile.TemporaryDirectory(prefix="crashlog-wire-") as directory:
        path = Path(directory) / "records"
        base = record(1, b"base\x00\xff")
        tail = record(2, b"new record\x00\xff")

        # The CLI writer must match an independently encoded record byte for byte.
        run("append", path, "123456789")
        require(path.read_bytes() == record(1, b"123456789"), "wire encoding")
        run("append", path, "", "--no-sync")
        require(
            path.read_bytes() == record(1, b"123456789") + record(2, b""),
            "empty record encoding",
        )
        require((path.stat().st_mode & 0o777) == 0o600, "new file permissions")

        for cut in range(len(tail) + 1):
            path.write_bytes(base + tail[:cut])
            complete = cut == len(tail)
            inspect(
                path,
                "clean" if cut == 0 or complete else "truncated",
                2 if complete else 1,
                len(base) + (len(tail) if complete else 0),
            )
            before = path.read_bytes()
            run("repair-tail", path, expected=64)
            require(path.read_bytes() == before, "repair requires explicit flag")
            run("repair-tail", path, "--truncate-tail")
            require(path.read_bytes() == (base + tail if complete else base), "repair prefix")
            run("repair-tail", path, "--truncate-tail")
            require(path.read_bytes() == (base + tail if complete else base), "repair idempotence")

        # One-bit corruption at every byte covers each metadata, checksum,
        # payload, and trailer field. Length corruption may imply truncation;
        # neither classification claims to know the physical failure cause.
        for offset in range(len(tail)):
            altered = bytearray(tail)
            altered[offset] ^= 1
            path.write_bytes(base + altered)
            result = run("inspect", path, expected=2)
            fields = dict(field.split("=", 1) for field in result.stdout.decode().split())
            require(int(fields["records"]) == 1, f"corruption accepted at {offset}")
            require(int(fields["valid_bytes"]) == len(base), "corrupt prefix boundary")
            if fields["state"] == "invalid":
                before = path.read_bytes()
                run("repair-tail", path, "--truncate-tail", expected=1)
                require(path.read_bytes() == before, "invalid record must not be truncated")
            else:
                require(fields["state"] == "truncated", fields)

        malformed = [
            (b"NOPE" + tail[4:], "bad-magic"),
            (tail[:4] + struct.pack("<I", 2) + tail[8:], "bad-version"),
            (tail[:8] + struct.pack("<Q", 3) + tail[16:], "bad-sequence"),
            (tail[:16] + struct.pack("<I", 1048577) + tail[20:], "bad-length"),
            (tail[:20] + bytes(4) + tail[24:], "bad-crc"),
            (tail[:-16] + b"FAIL" + tail[-12:], "bad-trailer"),
        ]
        for data, problem in malformed:
            path.write_bytes(base + data)
            inspect(path, "invalid", 1, len(base), problem)

        # Deterministic independent records of varied lengths, including the cap.
        rng = random.Random(0xC0FFEE)
        payloads = [rng.randbytes(length) for length in [0, 1, 7, 255, 4096, 1048576]]
        image = b"".join(record(i + 1, payload) for i, payload in enumerate(payloads))
        path.write_bytes(image)
        inspect(path, "clean", len(payloads), len(image), "none")

        path.write_bytes(record(1, b'\x00\n\xff"\\ A'))
        dumped = run("dump", path).stdout
        require(b'\\x00\\x0a\\xff\\x22\\x5c A' in dumped, "binary-safe dump escaping")
        path.write_bytes(base + tail[:27])
        before = path.read_bytes()
        run("append", path, "refuse", expected=1)
        require(path.read_bytes() == before, "append must refuse incomplete log")
        # Reject special files promptly rather than blocking in open on a FIFO.
        fifo = Path(directory) / "fifo"
        os.mkfifo(fifo)
        run("inspect", fifo, expected=1)
        run("inspect", directory, expected=1)
    print(f"PASS: {CHECKS} independent wire/CLI checks (struct + zlib oracle)")


if __name__ == "__main__":
    main()
