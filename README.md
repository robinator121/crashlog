# crashlog

A small C11 append-only binary log that makes an incomplete final record
observable. It is a storage-protocol experiment and reusable scanner, with an
explicit byte format, bounded payloads, CRC-32, single-writer locking, and an
operator-requested tail repair.

The central question is narrow: after an append stops at any byte, can a reader
identify the last fully valid prefix without trusting the interrupted write?
This project tests that question. It does not claim that a trailer or checksum
makes writes atomic or proves survival of a power failure.

## Build and run

Requirements: x86-64 Linux, a C11 compiler, make, and a linker supporting `--wrap`
for the C fault-injection tests. Python 3.9+ is used only by independent tests.
No root access or third-party runtime dependencies are needed. Clang is needed
for the provided sanitizer target.

```sh
make
./build/crashlog append /tmp/example.clog 'first observation'
./build/crashlog append /tmp/example.clog 'second observation'
./build/crashlog inspect /tmp/example.clog
./build/crashlog dump /tmp/example.clog
make test
make BUILD=build-clang CC=clang test
make sanitize
make adversarial
```

`append` requests `fdatasync` by default. Add `--no-sync` after the text to
observe buffered appends; that option removes the explicit synchronization
request. The CLI accepts text arguments; the library accepts binary payloads
from zero through 1,048,576 bytes. New files are opened with mode 0600, subject
to the process umask. Directory entries are not synchronized.

`inspect` reports `state`, record count, valid prefix length, file length, and
the first parsing problem. `dump` prints escaped payloads from validated records
and the same scan summary; a later bad record can produce a valid prefix on
stdout followed by exit code 2. Read commands do not modify the file.

Exit codes: 0 success/clean log; 1 system error or refused operation;
2 successfully inspected but incomplete/invalid input; 64 invalid CLI usage.
Locks are advisory and nonblocking. A competing reader/writer can therefore
cause an open/lock error rather than waiting.

## Recovery is an explicit decision

Copy the file before deliberately discarding a tail. Inspect it, then request:

```sh
./build/crashlog repair-tail /tmp/example.clog --truncate-tail
```

Only a `truncated` tail is eligible; a complete malformed record (`invalid`) is
refused unchanged. A clean log is left alone. Repair calls `ftruncate` and then
`fdatasync`. If synchronization fails, truncation may already have happened.

`truncated` means that the bytes are insufficient for the header or declared
record. It does **not** prove that the cause was an interrupted append. A
corrupted length can imply a missing payload; fewer than 24 trailing garbage
bytes are also structurally incomplete. The explicit flag accepts discarding
such a suffix. No scanner can recover the intended bytes from this format alone.

After *any* append error, inspect before retrying. A write or synchronization
error may leave an incomplete record, a complete visible record, or an unknown
durability state. Blind retries can duplicate an operation.

## Library boundary

`include/crashlog.h` and `build/libcrashlog.a` expose four operations:

- `cl_open`: open a regular file and hold a shared or exclusive advisory lock;
  the caller owns and closes the returned descriptor.
- `cl_scan`: validate the longest sequential prefix, optionally visiting each
  validated payload. The callback borrows the payload only during that call.
- `cl_append`: scan a clean file, append one record, optionally synchronize.
- `cl_repair_tail`: explicitly truncate an incomplete tail and synchronize.

Keep a writable `cl_open` handle for the whole writer lifetime. All access to
the same inode must cooperate with the lock; do not write through another
descriptor, alter descriptor flags, modify from a scan callback, or reuse an
inherited handle concurrently. `O_APPEND` handles are rejected for mutation
because Linux `pwrite` would ignore the requested offset. Scans use positional
I/O and do not change the descriptor's seek offset.

Externally serialize **all** operations on a handle, including calls from
multiple threads. `flock` does not serialize duplicated or inherited copies of
the same open-file description. A child must close its inherited handle before
opening an independent one. There is no internal thread mutex.

Appending rescans the whole file and allocates at most roughly 1 MiB for a
record; this is deliberately a correctness-first small-log design. It is not a
high-throughput database. No throughput claims are made.

The exact [wire format and design decisions](docs/ARCHITECTURE.md),
[known limitations](docs/LIMITATIONS.md), and
[recorded verification evidence](docs/VERIFICATION.md) are provided separately.

`make adversarial` runs the independently written seeded parser/repair oracle
and a deliberate demonstration of the excluded inherited-handle race. The
race program succeeds when it reproduces the documented boundary: two
unsupported concurrent appends through one inherited handle can overwrite
each other. This is evidence for the external-serialization requirement.
