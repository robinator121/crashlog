#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "crashlog.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t write_budget = SIZE_MAX;
static size_t write_chunk = SIZE_MAX;
static size_t read_chunk = SIZE_MAX;
static unsigned int write_interrupts;
static unsigned int read_interrupts;
static unsigned int sync_interrupts;
static bool zero_write;
static bool zero_read;
static bool sync_failure;
static bool stop_after_write;
static bool stop_after_sync;
static int notification_fd = -1;
static unsigned int assertions;

ssize_t __real_pwrite(int fd, const void *buffer, size_t count, off_t offset);
ssize_t __real_pread(int fd, void *buffer, size_t count, off_t offset);
int __real_fdatasync(int fd);

static void fail(const char *expression, int line)
{
    fprintf(stderr, "FAIL line %d: %s (errno=%d: %s)\n",
            line, expression, errno, strerror(errno));
    exit(1);
}

#define REQUIRE(expression) \
    do \
    { \
        assertions++; \
        if (!(expression)) \
        { \
            fail(#expression, __LINE__); \
        } \
    } while (0)

static void checkpoint(void)
{
    ssize_t count;

    do
    {
        count = write(notification_fd, "x", 1);
    }
    while (count < 0 && errno == EINTR);
    if (count != 1)
    {
        _exit(90);
    }
    for (;;)
    {
        pause();
    }
}

ssize_t __wrap_pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    ssize_t written;

    if (write_interrupts != 0)
    {
        write_interrupts--;
        errno = EINTR;
        return -1;
    }
    if (zero_write)
    {
        return 0;
    }
    if (write_budget == 0)
    {
        errno = ENOSPC;
        return -1;
    }
    if (count > write_chunk)
    {
        count = write_chunk;
    }
    if (count > write_budget)
    {
        count = write_budget;
    }
    written = __real_pwrite(fd, buffer, count, offset);
    if (written > 0)
    {
        write_budget -= (size_t)written;
        if (stop_after_write)
        {
            checkpoint();
        }
    }
    return written;
}

ssize_t __wrap_pread(int fd, void *buffer, size_t count, off_t offset)
{
    if (read_interrupts != 0)
    {
        read_interrupts--;
        errno = EINTR;
        return -1;
    }
    if (zero_read)
    {
        return 0;
    }
    if (count > read_chunk)
    {
        count = read_chunk;
    }
    return __real_pread(fd, buffer, count, offset);
}

/* glibc redirects these calls when _FILE_OFFSET_BITS=64 is defined, including
 * on x86-64. Wrap both symbol spellings so fault injection reaches real I/O.
 */
ssize_t __wrap_pwrite64(int fd, const void *buffer, size_t count, off_t offset)
{
    return __wrap_pwrite(fd, buffer, count, offset);
}

ssize_t __wrap_pread64(int fd, void *buffer, size_t count, off_t offset)
{
    return __wrap_pread(fd, buffer, count, offset);
}

int __wrap_fdatasync(int fd)
{
    int status;

    if (sync_interrupts != 0)
    {
        sync_interrupts--;
        errno = EINTR;
        return -1;
    }
    if (sync_failure)
    {
        errno = EIO;
        return -1;
    }
    status = __real_fdatasync(fd);
    if (status == 0 && stop_after_sync)
    {
        checkpoint();
    }
    return status;
}

static void reset_faults(void)
{
    write_budget = SIZE_MAX;
    write_chunk = SIZE_MAX;
    read_chunk = SIZE_MAX;
    write_interrupts = 0;
    read_interrupts = 0;
    sync_interrupts = 0;
    zero_write = false;
    zero_read = false;
    sync_failure = false;
    stop_after_write = false;
    stop_after_sync = false;
    notification_fd = -1;
}

static int fresh_log(const char *path)
{
    int fd;

    reset_faults();
    if (unlink(path) < 0)
    {
        REQUIRE(errno == ENOENT);
    }
    fd = cl_open(path, true, true);
    REQUIRE(fd >= 0);
    return fd;
}

static struct cl_scan_result scan_log(int fd)
{
    struct cl_scan_result scan;

    REQUIRE(cl_scan(fd, &scan, NULL, NULL) == 0);
    return scan;
}

static void expect_clean(int fd, uint64_t records)
{
    struct cl_scan_result scan = scan_log(fd);

    REQUIRE(scan.state == CL_CLEAN);
    REQUIRE(scan.problem == CL_NO_PROBLEM);
    REQUIRE(scan.records == records);
    REQUIRE(scan.valid_bytes == scan.file_bytes);
}

struct visit_context
{
    unsigned int calls;
    const unsigned char *large;
};

static int visit_record(uint64_t sequence, const unsigned char *payload,
                        uint32_t length, void *opaque)
{
    struct visit_context *context = opaque;
    static const unsigned char binary[] = {0, 10, 255, 34, 92};

    context->calls++;
    REQUIRE(sequence == context->calls);
    if (sequence == 1)
    {
        REQUIRE(length == 0);
    }
    else if (sequence == 2)
    {
        REQUIRE(length == sizeof(binary));
        REQUIRE(memcmp(payload, binary, sizeof(binary)) == 0);
    }
    else
    {
        REQUIRE(length == CL_MAX_PAYLOAD);
        REQUIRE(memcmp(payload, context->large, length) == 0);
    }
    return 0;
}

static int stop_visit(uint64_t sequence, const unsigned char *payload,
                      uint32_t length, void *context)
{
    (void)sequence;
    (void)payload;
    (void)length;
    (void)context;
    return 1;
}

static void test_round_trip(const char *path)
{
    static const unsigned char binary[] = {0, 10, 255, 34, 92};
    unsigned char *large = malloc(CL_MAX_PAYLOAD);
    struct visit_context context = {.calls = 0, .large = large};
    struct cl_scan_result scan;
    int fd = fresh_log(path);

    REQUIRE(large != NULL);
    for (uint32_t i = 0; i < CL_MAX_PAYLOAD; i++)
    {
        large[i] = (unsigned char)(i * UINT32_C(37));
    }
    expect_clean(fd, 0);
    REQUIRE(cl_append(fd, NULL, 0, true) == 0);
    REQUIRE(cl_append(fd, binary, sizeof(binary), false) == 0);
    REQUIRE(cl_append(fd, large, CL_MAX_PAYLOAD, true) == 0);
    REQUIRE(cl_scan(fd, &scan, visit_record, &context) == 0);
    REQUIRE(context.calls == 3);
    expect_clean(fd, 3);
    REQUIRE(cl_scan(fd, &scan, stop_visit, NULL) == -1);
    REQUIRE(errno == ECANCELED);
    REQUIRE(cl_append(fd, NULL, 1, false) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(cl_append(fd, large, CL_MAX_PAYLOAD + 1, false) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(cl_scan(fd, NULL, NULL, NULL) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(cl_repair_tail(fd, NULL) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(cl_repair_tail(fd, &scan) == 0);
    REQUIRE(scan.state == CL_CLEAN);
    REQUIRE(close(fd) == 0);
    free(large);
}

static void test_interrupted_io(const char *path)
{
    static const char payload[] = "short I/O is I/O";
    const size_t total = CL_HEADER_SIZE + sizeof(payload) - 1 + CL_TRAILER_SIZE;

    for (size_t cut = 0; cut < total; cut++)
    {
        int fd = fresh_log(path);
        struct cl_scan_result scan;
        off_t prefix;

        REQUIRE(cl_append(fd, "base", 4, true) == 0);
        prefix = scan_log(fd).valid_bytes;
        write_budget = cut;
        write_chunk = 3;
        read_chunk = 3;
        write_interrupts = 1;
        read_interrupts = 1;
        REQUIRE(cl_append(fd, payload, sizeof(payload) - 1, true) == -1);
        REQUIRE(errno == ENOSPC);
        reset_faults();
        scan = scan_log(fd);
        REQUIRE(scan.state == (cut == 0 ? CL_CLEAN : CL_TRUNCATED));
        REQUIRE(scan.records == 1);
        REQUIRE(scan.valid_bytes == prefix);
        REQUIRE(scan.file_bytes == prefix + (off_t)cut);
        if (cut != 0)
        {
            REQUIRE(cl_append(fd, "must refuse", 11, false) == -1);
            REQUIRE(errno == EILSEQ);
        }
        REQUIRE(cl_repair_tail(fd, &scan) == 0);
        expect_clean(fd, 1);
        write_chunk = 2;
        read_chunk = 2;
        write_interrupts = 2;
        read_interrupts = 2;
        sync_interrupts = 2;
        REQUIRE(cl_append(fd, payload, sizeof(payload) - 1, true) == 0);
        reset_faults();
        expect_clean(fd, 2);
        REQUIRE(close(fd) == 0);
    }
}

static void test_io_failures(const char *path)
{
    int fd = fresh_log(path);
    struct cl_scan_result scan;
    int flags;

    zero_write = true;
    REQUIRE(cl_append(fd, "x", 1, false) == -1);
    REQUIRE(errno == EIO);
    reset_faults();
    expect_clean(fd, 0);
    sync_failure = true;
    REQUIRE(cl_append(fd, "written but sync failed", 23, true) == -1);
    REQUIRE(errno == EIO);
    reset_faults();
    expect_clean(fd, 1);
    zero_read = true;
    REQUIRE(cl_scan(fd, &scan, NULL, NULL) == -1);
    REQUIRE(errno == EIO);
    REQUIRE(cl_repair_tail(fd, &scan) == -1);
    REQUIRE(errno == EIO);
    reset_faults();
    expect_clean(fd, 1);
    flags = fcntl(fd, F_GETFL);
    REQUIRE(flags >= 0);
    REQUIRE(fcntl(fd, F_SETFL, flags | O_APPEND) == 0);
    REQUIRE(cl_append(fd, "x", 1, false) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(fcntl(fd, F_SETFL, flags) == 0);
    REQUIRE(close(fd) == 0);
    fd = cl_open(path, false, false);
    REQUIRE(fd >= 0);
    REQUIRE(cl_append(fd, "x", 1, false) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(cl_repair_tail(fd, &scan) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(close(fd) == 0);
}

static void test_invalid_refuses_repair(const char *path)
{
    int fd = fresh_log(path);
    unsigned char bad = 0;
    struct cl_scan_result before;
    struct cl_scan_result after;

    REQUIRE(cl_append(fd, "valid", 5, true) == 0);
    REQUIRE(__real_pwrite(fd, &bad, 1, CL_HEADER_SIZE) == 1);
    before = scan_log(fd);
    REQUIRE(before.state == CL_INVALID);
    REQUIRE(before.problem == CL_BAD_CRC);
    REQUIRE(cl_repair_tail(fd, &after) == -1);
    REQUIRE(errno == EILSEQ);
    after = scan_log(fd);
    REQUIRE(after.file_bytes == before.file_bytes);
    REQUIRE(after.state == CL_INVALID);
    REQUIRE(close(fd) == 0);
}

static void test_locks_and_file_types(const char *path, const char *directory)
{
    int fd = fresh_log(path);
    int other;
    pid_t child;
    int status;

    child = fork();
    REQUIRE(child >= 0);
    if (child == 0)
    {
        close(fd);
        other = cl_open(path, true, false);
        if (other >= 0)
        {
            close(other);
            _exit(1);
        }
        _exit(errno == EWOULDBLOCK || errno == EAGAIN ? 0 : 2);
    }
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    other = cl_open(path, false, false);
    REQUIRE(other == -1);
    REQUIRE(errno == EWOULDBLOCK || errno == EAGAIN);
    REQUIRE(close(fd) == 0);
    fd = cl_open(path, false, false);
    REQUIRE(fd >= 0);
    other = cl_open(path, false, false);
    REQUIRE(other >= 0);
    REQUIRE(close(other) == 0);
    other = cl_open(path, true, false);
    REQUIRE(other == -1);
    REQUIRE(errno == EWOULDBLOCK || errno == EAGAIN);
    REQUIRE(close(fd) == 0);
    REQUIRE(cl_open(directory, false, false) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(cl_open(NULL, false, false) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(cl_open(path, false, true) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(unlink(path) == 0);
    REQUIRE(mkfifo(path, 0600) == 0);
    REQUIRE(cl_open(path, false, false) == -1);
    REQUIRE(errno == EINVAL);
    REQUIRE(unlink(path) == 0);
}

static void test_process_kill(const char *path, bool after_sync)
{
    int fd = fresh_log(path);
    int handshake[2];
    pid_t child;
    int status;
    char token;
    ssize_t count;
    struct cl_scan_result scan;

    REQUIRE(cl_append(fd, "base", 4, true) == 0);
    REQUIRE(close(fd) == 0);
    REQUIRE(pipe(handshake) == 0);
    child = fork();
    REQUIRE(child >= 0);
    if (child == 0)
    {
        alarm(10);
        close(handshake[0]);
        fd = cl_open(path, true, false);
        if (fd < 0)
        {
            _exit(91);
        }
        notification_fd = handshake[1];
        stop_after_sync = after_sync;
        stop_after_write = !after_sync;
        write_chunk = after_sync ? SIZE_MAX : 17;
        (void)cl_append(fd, "child payload", 13, true);
        _exit(92);
    }
    REQUIRE(close(handshake[1]) == 0);
    do
    {
        count = read(handshake[0], &token, 1);
    }
    while (count < 0 && errno == EINTR);
    REQUIRE(count == 1 && token == 'x');
    REQUIRE(kill(child, SIGKILL) == 0);
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    REQUIRE(close(handshake[0]) == 0);
    fd = cl_open(path, true, false);
    REQUIRE(fd >= 0);
    scan = scan_log(fd);
    REQUIRE(scan.state == (after_sync ? CL_CLEAN : CL_TRUNCATED));
    REQUIRE(scan.records == (after_sync ? 2U : 1U));
    if (!after_sync)
    {
        REQUIRE(scan.file_bytes - scan.valid_bytes == 17);
        REQUIRE(cl_repair_tail(fd, &scan) == 0);
        expect_clean(fd, 1);
    }
    REQUIRE(close(fd) == 0);
}

int main(void)
{
    char directory[] = "/tmp/crashlog-test-XXXXXX";
    char path[512];
    int length;

    alarm(90);
    REQUIRE(mkdtemp(directory) != NULL);
    length = snprintf(path, sizeof(path), "%s/data", directory);
    REQUIRE(length > 0 && (size_t)length < sizeof(path));
    test_round_trip(path);
    test_interrupted_io(path);
    test_io_failures(path);
    test_invalid_refuses_repair(path);
    test_locks_and_file_types(path, directory);
    test_process_kill(path, false);
    test_process_kill(path, true);
    REQUIRE(unlink(path) == 0);
    REQUIRE(rmdir(directory) == 0);
    printf("PASS: %u C assertions; every append byte cutoff; short/EINTR/failed I/O; "
           "locks; SIGKILL before/after sync\n", assertions);
    return 0;
}
