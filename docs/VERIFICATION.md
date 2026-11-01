# Verification evidence

Run on 2026-11-01 in the local x86-64 Linux environment. These are observed test
results, not benchmark estimates or evidence of physical power-failure safety.

Environment observed:

```text
cc (GCC) 16.2.1 20260810
clang version 22.1.8
Python 3.14.7
Linux 7.2.3-arch1-3 x86_64
```

## Passed commands

From the project root:

```sh
make test
make BUILD=build-clang CC=clang test
make sanitize
```

All three commands exited 0. Each built with `-Wall -Wextra -Wpedantic
-Wconversion -Wshadow -Werror` and reported:

```text
PASS: 1553 C assertions; every append byte cutoff; short/EINTR/failed I/O; locks; SIGKILL before/after sync
PASS: 894 independent wire/CLI checks (struct + zlib oracle)
```

The sanitizer build used Clang at `-O1`, `-fno-omit-frame-pointer`, and
`-fsanitize=address,undefined` for compilation and linking. It reported no
AddressSanitizer or UndefinedBehaviorSanitizer diagnostics. Assembly is not part
of this project. There are no benchmark results or performance claims.

The C checks include empty/binary/maximum-sized payloads, visitor cancellation,
argument validation, every cutoff of a 56-byte append, interrupted/short reads
and writes, no-progress I/O, sync interruption/failure, `O_APPEND` rejection,
read-only rejection, advisory lock conflicts, shared readers, special files,
and actual child SIGKILL checkpoints after a 17-byte partial write and after a
complete synchronized append. A 90-second parent alarm bounds the harness;
checkpoint children have their own ten-second alarm.

The Python checks independently encode bytes with `struct` and `zlib.crc32`.
They include all cutoffs and every single-byte one-bit corruption of a 52-byte
record, malformed magic/version/sequence/length/checksum/trailer, explicit
repair authorization, repair idempotence, refusal to change invalid records,
deterministic payload lengths through 1 MiB, binary dump escaping, and FIFO /
directory rejection. Each CLI subprocess has a ten-second timeout.

## Defects found and corrected before acceptance

The first fault-injection run failed at the expected ENOSPC assertion. Inspection
showed glibc redirected `_FILE_OFFSET_BITS=64` positional I/O to `pread64` and
`pwrite64`, bypassing the initial linker wrappers for `pread` / `pwrite`.
The test harness now wraps both spellings. The production implementation did
not need a fallback or test hook. All three full verification commands above
passed after the correction.

Independent review called out that `flock` does not serialize operations on
the same open-file description, including threads and `dup` / `fork` copies.
The explicit single-owner contract now requires external serialization of all
same-handle operations, and closing inherited handles before reopening in a
child. This concurrency is excluded; no internal mutex or unsupported
multiwriter guarantee was added.

## Not established

No physical power-loss, kernel-crash, controller-cache, network-filesystem,
multiwriter, exactly-once-delivery, or performance guarantee is established.
No Valgrind result is claimed here. The independent QA report may add findings
after this author verification record.
