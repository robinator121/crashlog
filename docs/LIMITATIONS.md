# Known limitations

- Process termination and synthetic byte cutoffs are tested. Physical power
  failure, filesystem crash/replay, torn sectors, and lying storage caches are
  not tested. `fdatasync` is requested; hardware guarantees are not fabricated.
- No directory `fsync`; creating a filename is outside the persistence claim.
- CRC-32 can collide and can be forged. The format is for accidental damage
  detection, not hostile authenticated input or cryptographic integrity.
- A corrupted length may look like truncation. Fewer than 24 arbitrary tail
  bytes are also classified as truncated. Repair requires explicit consent to
  discard that suffix; it cannot know the original cause.
- Complete mid-log corruption stops scanning. The tool does not salvage later
  records, reconstruct damaged bytes, or automatically repair invalid input.
- Locks are advisory Linux `flock` locks. All file access must cooperate. Shared
  open-file descriptions inherited through `fork` also share lock lifetime;
  callers must not mutate concurrently through inherited or duplicated handles.
  Externally serialize all same-handle operations across threads as well; no
  internal mutex is provided. Close inherited handles before independently
  reopening in a child. Network filesystem locking semantics are not validated.
- One cooperating writer; no transactions spanning multiple records, external
  side effects, exactly-once delivery, idempotency keys, concurrent reads during
  append, or multiwriter ordering protocol.
- Every append rescans the file. Total work for many small records grows
  quadratically with record count. A record allocation is bounded near 1 MiB,
  but a large valid file can still require substantial scan time.
- A synchronization error can follow a fully visible record. Inspect and
  reconcile before retrying; the API cannot infer the caller's application
  operation or safely roll it back.
- A repair synchronization error can occur after `ftruncate` changed the file.
  There is no implicit backup, journal of repair operations, or rollback.
- Linux with signed 64-bit `off_t` is required and checked at compile time.
  The test harness requires a GNU-compatible linker `--wrap` facility; Clang
  sanitizer support and Python 3.9+ are verification dependencies only.
- No deployment, benchmark, or real power-failure result is claimed.
