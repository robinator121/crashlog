# Independent adversarial review

Recorded 2026-11-01. Production source was unchanged by these checks.
This is an independent engineering check, not a proof of storage durability.

## Result

No production correctness defect was demonstrated within the documented
single-owner, cooperating-lock contract. One concurrency contract gap was
identified and clarified: every operation on the same open-file description
requires external serialization. Inherited/duplicated handles and threads
share a `flock` lock; it cannot serialize those callers against one another.

The header, README, architecture, and
limitations make this precondition explicit. Supporting concurrent shared
handles would require a different synchronization design. This review did not
add a mutex or claim multiwriter support.

## Checks performed

Read the public header, implementation, CLI, original C fault-injection tests,
independent wire tests, architecture, and limitations. Reviewed:

- Header/trailer bounds, checksum coverage, zero-length payload handling,
  maximum-length allocation, and little-endian encoding.
- Signed file-offset additions: available-byte checks bound scanner offsets;
  append checks the signed 64-bit limit before extending the file.
- EINTR, short and no-progress reads/writes, callback cancellation, cleanup,
  O_APPEND rejection, and synchronization error semantics.
- Advisory-lock ownership, fork/dup semantics, callback lifetime, and the
  explicit exclusion of concurrent mutation during a scan.
- Repair policy: invalid complete records remain unchanged; structural
  incompleteness authorizes only the valid prefix when explicitly requested.
- Accuracy of documented persistence and test claims: process SIGKILL and
  synthetic cutoffs do not establish physical power-loss safety.

Added `tests/adversarial_review.py`, a separate seeded oracle using Python
`struct` and `zlib`. It generated **609 images**, including every cutoff of a
four-record stream, 100 images with several random bit changes, trailing
garbage, and 50 arbitrary binary images. Each image was independently
classified, inspected, offered for explicit repair, and offered an append.
Checks require exact state/problem/prefix/count/size output, no inspection
mutation, no invalid repair/append mutation, and exact independently encoded
post-repair appended bytes.

The oracle completed **4263 checks**, exit 0, against both the ordinary
executable and the Clang ASan/UBSan executable. Sanitized subprocesses used
`ASAN_OPTIONS=detect_leaks=1:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1`; no sanitizer diagnostics were observed.

Raw command output is saved in:

- `verification/independent-parser.txt`
- `verification/independent-parser-sanitize.txt`

## Reproduced boundary

`tests/shared_handle_boundary.c` intentionally violates the single-owner
contract. Two children inherit one writable descriptor. Linker barriers stop
both after their EOF scans and before either positional write. Both append
calls then return success, but one clean record remains: both selected the
same sequence and offset. Identical payloads make the observation a lost
append rather than a checksum accident.

Actual output:

```text
unsupported shared-handle concurrency: 2 successful appends, 1 stored record(s)
```

The reproducer exits 0 only when this excluded boundary is reproduced. Its
success is not a passing multiwriter guarantee. Source and command logs are
preserved so the documented limitation is experimentally reviewable:

- `verification/shared-handle-build.txt`
- `verification/shared-handle-boundary.txt`

`make adversarial` reproduces the ordinary parser review and boundary
demonstration. The sanitized parser review can be rerun after `make sanitize`:

```sh
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
    python3 tests/adversarial_review.py build-sanitize/crashlog
```

## Remaining limits

No real power-loss, kernel crash, filesystem recovery, disk/controller fault,
network-filesystem lock behavior, hostile authenticity, or performance test
was performed. A corrupt length can classify a physically complete tail as
structurally truncated; this is explicitly documented and cannot be resolved
from this format alone. Very large valid files can take substantial scan time.
The fuzz corpus is deterministic and finite, not exhaustive over every byte
stream or platform.
