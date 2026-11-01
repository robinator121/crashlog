# Architecture and decisions

## Hypothesis and invariants

The scanner can identify the longest consecutive prefix of fully encoded,
checksummed records after every deterministic byte cutoff of an append. The
test oracle is that prefix, not a timing result or a claim of physical storage
atomicity. The implementation uses file descriptors, fixed arrays, bounded
allocation, and explicit loops; no framework is needed.

Invariants:

1. Sequences start at one and increase by one. No records after the first
   malformed/incomplete record are accepted.
2. On a successful scan, `valid_bytes` ends exactly after the last validated
   trailer and `records` counts only accepted records. `file_bytes` is the size
   snapshot taken at scan start. The caller excludes concurrent mutation.
3. Payload lengths never exceed 1,048,576 bytes. All offset additions are
   checked against existing file bounds or the signed 64-bit file-offset limit
   before I/O. No on-disk C struct layout is used.
4. Append requires a completely clean prefix. It never repairs or overwrites
   an unexplained tail. Repair is a separate destructive operation.
5. The callback receives bytes only after their record passes all checks. It
   may abort a scan, but may not mutate/close the file or keep the borrowed
   pointer beyond its invocation. A failed scan leaves no authoritative result.

## Wire format, version 1

There is no separate file header. An empty file is a valid zero-record log.
Each record has a 24-byte header, the payload, and a 16-byte trailer. All integer
fields use little-endian order; ASCII constants are raw bytes. Maximum encoded
record size is 1,048,616 bytes.

| Relative byte offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `CLG1` |
| 4 | 4 | Version, unsigned 32-bit, value 1 |
| 8 | 8 | Sequence, unsigned 64-bit, starting at 1 |
| 16 | 4 | Payload length, unsigned 32-bit |
| 20 | 4 | CRC-32 of header bytes 0–19 followed by payload |
| 24 | length | Arbitrary payload bytes |
| 24 + length | 4 | ASCII `DONE` |
| 28 + length | 4 | Repeated payload length |
| 32 + length | 8 | Repeated sequence |

CRC is the reflected IEEE CRC-32 algorithm: polynomial `0xedb88320`, initial
state `0xffffffff`, final complement. Python's standard `zlib.crc32` is the
independent wire oracle; its canonical `123456789` check value is `0xcbf43926`.
The trailer is validated separately. CRC collisions are possible and deliberate
attackers can forge it. This format has no authenticity claim.

## State machine

At each record boundary, the scanner checks available header bytes, magic,
version, bounded length, expected sequence, available complete record bytes,
CRC, and trailer, in that order. It stops immediately at the first failure.

- `clean`: every byte belongs to a valid record, including the empty file.
- `truncated`: fewer than 24 header bytes remain, or a syntactically accepted
  header declares a record longer than the bytes remaining.
- `invalid`: a complete available header or record violates a validation check.
- I/O, allocation, or visitor failure: return -1 with `errno`; do not authorize
  repair based on the partially filled result.

These states classify bytes. They do not identify the physical cause. For
example, changing the length field of an otherwise complete record can produce
`truncated`, and a complete trailer in cache does not establish durability.

## Append and synchronization

Open uses `O_CLOEXEC` and `O_NONBLOCK`; regular-file I/O ignores the latter,
while opening a FIFO for inspection cannot block before it is rejected by
`fstat`. A read handle holds shared `flock`; mutation requires an exclusive
handle. Locks are nonblocking and advisory. The contract is one cooperating
writer and no concurrent reader while it writes, not arbitrary multiwriter
transaction isolation.

The caller must externally serialize every operation on the same handle.
Threads, `dup` copies, and inherited descriptors share the same open-file
description; its `flock` is not a mutex for those users. A child must close an
inherited handle before opening a new one. This contract avoids adding a
threading framework to an explicitly single-owner primitive.

Append validates arguments, write mode, and the current whole log. It constructs
one encoded record in bounded memory, then performs positional writes until
complete, retrying EINTR and continuing short writes. A zero-length write while
bytes remain becomes EIO. The entire record can span multiple system calls;
neither one `pwrite` nor the trailer is claimed to be atomic.

With synchronization requested, a successful append includes a successful
`fdatasync` (EINTR is retried). Its durability relies on the OS, filesystem,
storage stack, and hardware honoring that contract. No parent-directory sync is
performed, so this does not cover survival of a newly created filename after
power loss. A sync failure cannot be rolled back safely by guessing: the
complete record may already be present. The caller must inspect/reconcile.

Repair rescans under the exclusive lock, refuses `invalid`, leaves `clean`
alone, and only then truncates `truncated` to `valid_bytes`. It synchronizes the
truncation. It makes no automatic backup. Operators should preserve evidence
before choosing that destructive action.

## Alternatives rejected

- Database or journaling library: useful in production, but it hides this
  experiment's byte protocol and fault boundary.
- Raw on-disk C structs: padding, alignment, and byte order would become an
  accidental file format.
- Memory mapping: adds mapping lifetime and writeback questions without making
  record commit atomic or eliminating synchronization requirements.
- Scanning past corruption for another magic: would silently skip data and
  accept accidental magic in a payload. This implementation preserves one
  sequential prefix and diagnostic cause.
- Automatic repair while opening: destroys evidence and merges observation
  with an irreversible policy choice.
- Mutable tail index or cached writer state: avoids repeated scanning but
  introduces another recovery protocol. Add it only for a measured workload.

## Falsification and evidence boundaries

C tests force every byte cutoff of an append via real short writes followed by
ENOSPC. They also inject interrupted reads/writes/syncs, zero progress, and sync
failure after a complete write. The test linker wraps both glibc's `pread64` /
`pwrite64` spelling and the ordinary spelling; production code has no injection
branches. The initial test run exposed this symbol-redirection detail, which
was corrected before accepting the fault tests.

A separately encoded Python oracle checks writer bytes, every cutoff, every
single-byte one-bit corruption of a short record, malformed field categories,
binary escaping, maximum lengths, and explicit/non-destructive repair policy.
Selected actual SIGKILL checkpoints demonstrate a partial process write and a
complete process write after `fdatasync`. They do not simulate kernel crash,
controller reordering, disk loss, or physical power removal. Random payloads
are deterministic. No benchmark or speedup claim is included.
