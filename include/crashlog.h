#ifndef CRASHLOG_H
#define CRASHLOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CL_MAX_PAYLOAD UINT32_C(1048576)
#define CL_HEADER_SIZE 24U
#define CL_TRAILER_SIZE 16U

enum cl_state
{
    CL_CLEAN,
    CL_TRUNCATED,
    CL_INVALID
};

enum cl_problem
{
    CL_NO_PROBLEM,
    CL_SHORT_HEADER,
    CL_BAD_MAGIC,
    CL_BAD_VERSION,
    CL_BAD_LENGTH,
    CL_BAD_SEQUENCE,
    CL_SHORT_RECORD,
    CL_BAD_CRC,
    CL_BAD_TRAILER
};

struct cl_scan_result
{
    enum cl_state state;
    enum cl_problem problem;
    off_t valid_bytes;
    off_t file_bytes;
    uint64_t records;
};

/* Payload is borrowed only for the call; NULL is allowed for an empty record.
 * Return zero to continue or nonzero to stop (cl_scan then fails with ECANCELED).
 * The callback must not modify or close the scanned file descriptor.
 */
typedef int (*cl_visit_fn)(uint64_t sequence, const unsigned char *payload,
                          uint32_t length, void *context);

/* Open a regular file and acquire a nonblocking advisory flock. Read handles
 * hold a shared lock; writable handles hold an exclusive lock. New files are
 * mode 0600. The caller owns the returned descriptor and must close it.
 * Do not mutate the inode outside this API while any handle is in use.
 * Externally serialize all operations on the same handle: flock does not
 * serialize threads or duplicated/inherited copies of a file description.
 * A child must close an inherited handle before opening its own handle.
 */
int cl_open(const char *path, bool writable, bool create);

/* Return 0 for a completed scan, including malformed input, or -1 for an I/O,
 * allocation, or callback error. result is authoritative only on return 0.
 * Validation stops at the first incomplete or invalid record.
 */
int cl_scan(int fd, struct cl_scan_result *result, cl_visit_fn visit, void *context);

/* Require a writable handle from cl_open and a clean log. sync_data requests
 * fdatasync after writing; a failure can leave a partial OR complete record.
 * Retrying append blindly after an error can therefore duplicate a record.
 */
int cl_append(int fd, const void *payload, uint32_t length, bool sync_data);

/* Explicit destructive operation: remove only a structurally incomplete tail.
 * A complete but corrupt record returns -1/EILSEQ without changing the file.
 * before describes the scan even when an invalid tail is refused. A clean log
 * is a no-op. Successful truncation is followed by fdatasync. On sync failure,
 * the truncation may already have occurred; inspect before retrying.
 */
int cl_repair_tail(int fd, struct cl_scan_result *before);

const char *cl_state_name(enum cl_state state);
const char *cl_problem_name(enum cl_problem problem);

#endif
