#!/usr/bin/env python3
"""Independent seeded parser/repair review; never modifies non-temporary files."""

from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import zlib


BINARY = Path(sys.argv[1]).resolve()
CHECKS = 0


def require(condition, detail):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(detail)


def encode(sequence, payload):
    metadata = struct.pack("<4sIQI", b"CLG1", 1, sequence, len(payload))
    return (metadata + struct.pack("<I", zlib.crc32(metadata + payload)) + payload
            + struct.pack("<4sIQ", b"DONE", len(payload), sequence))


def classify(image):
    offset = 0
    records = 0
    while offset < len(image):
        remaining = image[offset:]
        if len(remaining) < 24:
            return "truncated", "short-header", records, offset
        magic, version, sequence, length, checksum = struct.unpack("<4sIQII", remaining[:24])
        for invalid, problem in (
            (magic != b"CLG1", "bad-magic"),
            (version != 1, "bad-version"),
            (length > 1048576, "bad-length"),
            (sequence != records + 1, "bad-sequence"),
        ):
            if invalid:
                return "invalid", problem, records, offset
        total = 40 + length
        if len(remaining) < total:
            return "truncated", "short-record", records, offset
        if zlib.crc32(remaining[:20] + remaining[24:24 + length]) != checksum:
            return "invalid", "bad-crc", records, offset
        trailer = struct.unpack("<4sIQ", remaining[24 + length:total])
        if trailer != (b"DONE", length, sequence):
            return "invalid", "bad-trailer", records, offset
        offset += total
        records += 1
    return "clean", "none", records, offset


def invoke(*arguments):
    return subprocess.run([str(BINARY), *map(str, arguments)], capture_output=True,
                          timeout=10, check=False)


def check_image(path, image):
    path.write_bytes(image)
    state, problem, records, offset = classify(image)
    inspected = invoke("inspect", path)
    require(inspected.returncode == (0 if state == "clean" else 2), inspected)
    fields = dict(piece.split("=", 1) for piece in inspected.stdout.decode().split())
    require(fields == {"state": state, "problem": problem, "records": str(records),
                       "valid_bytes": str(offset), "file_bytes": str(len(image))}, fields)
    require(path.read_bytes() == image, "inspection changed bytes")
    repaired = invoke("repair-tail", path, "--truncate-tail")
    require(repaired.returncode == (1 if state == "invalid" else 0), repaired)
    expected = image[:offset] if state == "truncated" else image
    require(path.read_bytes() == expected, "repair changed unexpected bytes")
    if state != "invalid":
        appended = invoke("append", path, "review", "--no-sync")
        require(appended.returncode == 0, appended)
        after = path.read_bytes()
        require(after == expected + encode(records + 1, b"review"), "post-repair append")
    else:
        appended = invoke("append", path, "review", "--no-sync")
        require(appended.returncode == 1, appended)
        require(path.read_bytes() == expected, "append changed invalid log")


def main():
    rng = random.Random(0xADD0FF5E7)
    valid = b"".join(encode(i + 1, rng.randbytes(size))
                     for i, size in enumerate((0, 1, 31, 257)))
    images = [b"", valid]
    images.extend(valid[:cut] for cut in range(len(valid) + 1))
    for _ in range(100):
        altered = bytearray(valid)
        for _ in range(rng.randrange(1, 5)):
            altered[rng.randrange(len(altered))] ^= 1 << rng.randrange(8)
        images.append(bytes(altered))
    images.extend(valid + rng.randbytes(size) for size in (1, 7, 23, 24, 25, 100, 1024))
    images.extend(rng.randbytes(rng.randrange(4097)) for _ in range(50))
    with tempfile.TemporaryDirectory(prefix="crashlog-adversarial-") as directory:
        path = Path(directory) / "log"
        for image in images:
            check_image(path, image)
    print(f"PASS: {len(images)} independently classified images; {CHECKS} parser/repair/append checks")


if __name__ == "__main__":
    main()
