#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "crashlog.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(off_t) == sizeof(int64_t), "64-bit file offsets required");

static uint32_t read_u32(const unsigned char *bytes)
{
    uint32_t value = 0;

    for (unsigned int i = 0; i < 4; i++)
    {
        value |= (uint32_t)bytes[i] << (i * 8U);
    }
    return value;
}

static uint64_t read_u64(const unsigned char *bytes)
{
    uint64_t value = 0;

    for (unsigned int i = 0; i < 8; i++)
    {
        value |= (uint64_t)bytes[i] << (i * 8U);
    }
    return value;
}

static void write_u32(unsigned char *bytes, uint32_t value)
{
    for (unsigned int i = 0; i < 4; i++)
    {
        bytes[i] = (unsigned char)(value >> (i * 8U));
    }
}

static void write_u64(unsigned char *bytes, uint64_t value)
{
    for (unsigned int i = 0; i < 8; i++)
    {
        bytes[i] = (unsigned char)(value >> (i * 8U));
    }
}

/* IEEE CRC-32, reflected polynomial. Call with UINT32_MAX, then complement.
 * It detects accidental corruption; it is neither authentication nor a
 * persistence guarantee. Metadata bytes 0..19 participate in the checksum.
 */
static uint32_t crc_update(uint32_t crc, const unsigned char *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        crc ^= bytes[i];
        for (unsigned int bit = 0; bit < 8; bit++)
        {
            if ((crc & UINT32_C(1)) != 0)
            {
                crc = (crc >> 1) ^ UINT32_C(0xedb88320);
            }
            else
            {
                crc >>= 1;
            }
        }
    }
    return crc;
}

static int read_exact(int fd, void *buffer, size_t length, off_t offset)
{
    unsigned char *bytes = buffer;
    size_t done = 0;

    while (done < length)
    {
        ssize_t count = pread(fd, bytes + done, length - done,
                              offset + (off_t)done);
        if (count < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (count == 0)
        {
            /* The stat snapshot promised these bytes. A concurrent truncate
             * or an I/O anomaly is an error, not permission to repair.
             */
            errno = EIO;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

static int write_exact(int fd, const void *buffer, size_t length, off_t offset)
{
    const unsigned char *bytes = buffer;
    size_t done = 0;

    while (done < length)
    {
        ssize_t count = pwrite(fd, bytes + done, length - done,
                               offset + (off_t)done);
        if (count < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (count == 0)
        {
            errno = EIO;
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

static int sync_file(int fd)
{
    int status;

    do
    {
        status = fdatasync(fd);
    }
    while (status < 0 && errno == EINTR);
    return status;
}

static int check_writable(int fd)
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0)
    {
        return -1;
    }
    /* Linux pwrite on an O_APPEND descriptor ignores its explicit offset. */
    if ((flags & O_ACCMODE) != O_RDWR || (flags & O_APPEND) != 0)
    {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int cl_open(const char *path, bool writable, bool create)
{
    int flags = O_CLOEXEC | O_NONBLOCK | (writable ? O_RDWR : O_RDONLY);
    struct stat info;
    int fd;
    int status;

    if (path == NULL || (create && !writable))
    {
        errno = EINVAL;
        return -1;
    }
    if (create)
    {
        flags |= O_CREAT;
    }
    fd = open(path, flags, 0600);
    if (fd < 0)
    {
        return -1;
    }
    do
    {
        status = flock(fd, (writable ? LOCK_EX : LOCK_SH) | LOCK_NB);
    }
    while (status < 0 && errno == EINTR);
    if (status < 0 || fstat(fd, &info) < 0)
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(info.st_mode))
    {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    return fd;
}

int cl_scan(int fd, struct cl_scan_result *result, cl_visit_fn visit, void *context)
{
    struct stat info;
    off_t cursor = 0;
    uint64_t records = 0;

    if (result == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (fstat(fd, &info) < 0)
    {
        return -1;
    }
    if (!S_ISREG(info.st_mode) || info.st_size < 0)
    {
        errno = EINVAL;
        return -1;
    }
    *result = (struct cl_scan_result)
    {
        .state = CL_CLEAN,
        .problem = CL_NO_PROBLEM,
        .valid_bytes = 0,
        .file_bytes = info.st_size,
        .records = 0
    };

    while (cursor < info.st_size)
    {
        unsigned char header[CL_HEADER_SIZE];
        unsigned char trailer[CL_TRAILER_SIZE];
        unsigned char *payload = NULL;
        uint64_t remaining = (uint64_t)(info.st_size - cursor);
        uint64_t sequence;
        uint64_t total;
        uint32_t length;
        uint32_t checksum;

        if (remaining < CL_HEADER_SIZE)
        {
            result->state = CL_TRUNCATED;
            result->problem = CL_SHORT_HEADER;
            return 0;
        }
        if (read_exact(fd, header, sizeof(header), cursor) < 0)
        {
            return -1;
        }
        result->state = CL_INVALID;
        if (memcmp(header, "CLG1", 4) != 0)
        {
            result->problem = CL_BAD_MAGIC;
            return 0;
        }
        if (read_u32(header + 4) != UINT32_C(1))
        {
            result->problem = CL_BAD_VERSION;
            return 0;
        }
        length = read_u32(header + 16);
        if (length > CL_MAX_PAYLOAD)
        {
            result->problem = CL_BAD_LENGTH;
            return 0;
        }
        sequence = read_u64(header + 8);
        if (records == UINT64_MAX || sequence != records + 1)
        {
            result->problem = CL_BAD_SEQUENCE;
            return 0;
        }
        total = CL_HEADER_SIZE + (uint64_t)length + CL_TRAILER_SIZE;
        if (remaining < total)
        {
            result->state = CL_TRUNCATED;
            result->problem = CL_SHORT_RECORD;
            return 0;
        }
        if (length != 0)
        {
            payload = malloc(length);
            if (payload == NULL)
            {
                return -1;
            }
            if (read_exact(fd, payload, length, cursor + CL_HEADER_SIZE) < 0)
            {
                int saved_errno = errno;
                free(payload);
                errno = saved_errno;
                return -1;
            }
        }
        if (read_exact(fd, trailer, sizeof(trailer),
                       cursor + CL_HEADER_SIZE + (off_t)length) < 0)
        {
            int saved_errno = errno;
            free(payload);
            errno = saved_errno;
            return -1;
        }
        checksum = crc_update(UINT32_MAX, header, 20);
        checksum = ~crc_update(checksum, payload, length);
        if (read_u32(header + 20) != checksum)
        {
            free(payload);
            result->problem = CL_BAD_CRC;
            return 0;
        }
        if (memcmp(trailer, "DONE", 4) != 0 ||
            read_u32(trailer + 4) != length ||
            read_u64(trailer + 8) != sequence)
        {
            free(payload);
            result->problem = CL_BAD_TRAILER;
            return 0;
        }
        if (visit != NULL && visit(sequence, payload, length, context) != 0)
        {
            free(payload);
            errno = ECANCELED;
            return -1;
        }
        free(payload);
        cursor += (off_t)total;
        records++;
        result->state = CL_CLEAN;
        result->problem = CL_NO_PROBLEM;
        result->valid_bytes = cursor;
        result->records = records;
    }
    return 0;
}

int cl_append(int fd, const void *payload, uint32_t length, bool sync_data)
{
    struct cl_scan_result scan;
    unsigned char *record;
    unsigned char *trailer;
    size_t total;
    uint32_t checksum;
    int status;

    if (length > CL_MAX_PAYLOAD || (length != 0 && payload == NULL))
    {
        errno = EINVAL;
        return -1;
    }
    if (check_writable(fd) < 0 || cl_scan(fd, &scan, NULL, NULL) < 0)
    {
        return -1;
    }
    if (scan.state != CL_CLEAN)
    {
        errno = EILSEQ;
        return -1;
    }
    total = CL_HEADER_SIZE + (size_t)length + CL_TRAILER_SIZE;
    if (scan.records == UINT64_MAX ||
        (uint64_t)scan.valid_bytes > (uint64_t)INT64_MAX - total)
    {
        errno = EOVERFLOW;
        return -1;
    }
    record = malloc(total);
    if (record == NULL)
    {
        return -1;
    }
    memcpy(record, "CLG1", 4);
    write_u32(record + 4, UINT32_C(1));
    write_u64(record + 8, scan.records + 1);
    write_u32(record + 16, length);
    if (length != 0)
    {
        memcpy(record + CL_HEADER_SIZE, payload, length);
    }
    checksum = crc_update(UINT32_MAX, record, 20);
    checksum = ~crc_update(checksum, record + CL_HEADER_SIZE, length);
    write_u32(record + 20, checksum);
    trailer = record + CL_HEADER_SIZE + length;
    memcpy(trailer, "DONE", 4);
    write_u32(trailer + 4, length);
    write_u64(trailer + 8, scan.records + 1);

    status = write_exact(fd, record, total, scan.valid_bytes);
    if (status < 0)
    {
        int saved_errno = errno;
        free(record);
        errno = saved_errno;
        return -1;
    }
    free(record);
    if (sync_data)
    {
        return sync_file(fd);
    }
    return 0;
}

int cl_repair_tail(int fd, struct cl_scan_result *before)
{
    if (before == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (check_writable(fd) < 0 || cl_scan(fd, before, NULL, NULL) < 0)
    {
        return -1;
    }
    if (before->state == CL_INVALID)
    {
        errno = EILSEQ;
        return -1;
    }
    if (before->state == CL_CLEAN)
    {
        return 0;
    }
    if (ftruncate(fd, before->valid_bytes) < 0)
    {
        return -1;
    }
    return sync_file(fd);
}

const char *cl_state_name(enum cl_state state)
{
    switch (state)
    {
        case CL_CLEAN: return "clean";
        case CL_TRUNCATED: return "truncated";
        case CL_INVALID: return "invalid";
    }
    return "unknown";
}

const char *cl_problem_name(enum cl_problem problem)
{
    switch (problem)
    {
        case CL_NO_PROBLEM: return "none";
        case CL_SHORT_HEADER: return "short-header";
        case CL_BAD_MAGIC: return "bad-magic";
        case CL_BAD_VERSION: return "bad-version";
        case CL_BAD_LENGTH: return "bad-length";
        case CL_BAD_SEQUENCE: return "bad-sequence";
        case CL_SHORT_RECORD: return "short-record";
        case CL_BAD_CRC: return "bad-crc";
        case CL_BAD_TRAILER: return "bad-trailer";
    }
    return "unknown";
}
