#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "crashlog.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s append FILE TEXT [--no-sync]\n"
            "  %s inspect FILE\n"
            "  %s dump FILE\n"
            "  %s repair-tail FILE --truncate-tail\n",
            program, program, program, program);
}

static int print_record(uint64_t sequence, const unsigned char *payload,
                        uint32_t length, void *context)
{
    (void)context;
    if (printf("%" PRIu64 " length=%" PRIu32 " data=\"", sequence, length) < 0)
    {
        return -1;
    }
    for (uint32_t i = 0; i < length; i++)
    {
        unsigned char byte = payload[i];
        int status;

        if (byte >= 32 && byte <= 126 && byte != '\\' && byte != '"')
        {
            status = putchar(byte);
        }
        else
        {
            status = printf("\\x%02x", (unsigned int)byte);
        }
        if (status < 0)
        {
            return -1;
        }
    }
    return puts("\"") < 0 ? -1 : 0;
}

static int print_scan(const struct cl_scan_result *scan)
{
    return printf("state=%s records=%" PRIu64 " valid_bytes=%" PRIdMAX
                  " file_bytes=%" PRIdMAX " problem=%s\n",
                  cl_state_name(scan->state), scan->records,
                  (intmax_t)scan->valid_bytes, (intmax_t)scan->file_bytes,
                  cl_problem_name(scan->problem)) < 0 ? -1 : 0;
}

int main(int argc, char **argv)
{
    struct cl_scan_result scan;
    bool append;
    bool inspect;
    bool dump;
    bool repair;
    int fd;
    int result = 0;

    if (argc < 3)
    {
        usage(argv[0]);
        return 64;
    }
    append = strcmp(argv[1], "append") == 0;
    inspect = strcmp(argv[1], "inspect") == 0;
    dump = strcmp(argv[1], "dump") == 0;
    repair = strcmp(argv[1], "repair-tail") == 0;
    if ((!append && !inspect && !dump && !repair) ||
        (append && argc != 4 && argc != 5) ||
        (append && argc == 5 && strcmp(argv[4], "--no-sync") != 0) ||
        ((inspect || dump) && argc != 3) ||
        (repair && (argc != 4 || strcmp(argv[3], "--truncate-tail") != 0)))
    {
        usage(argv[0]);
        return 64;
    }
    fd = cl_open(argv[2], append || repair, append);
    if (fd < 0)
    {
        perror("open/lock");
        return 1;
    }
    if (append)
    {
        size_t length = strlen(argv[3]);

        if (length > CL_MAX_PAYLOAD)
        {
            fprintf(stderr, "payload exceeds %" PRIu32 " bytes\n", CL_MAX_PAYLOAD);
            result = 1;
        }
        else if (cl_append(fd, argv[3], (uint32_t)length, argc != 5) < 0)
        {
            perror("append (inspect before retrying)");
            result = 1;
        }
    }
    else if (repair)
    {
        if (cl_repair_tail(fd, &scan) < 0)
        {
            perror("repair-tail (complete corruption is refused)");
            result = 1;
        }
        else if (printf("previous_state=%s removed_bytes=%" PRIdMAX "\n",
                        cl_state_name(scan.state),
                        (intmax_t)(scan.file_bytes - scan.valid_bytes)) < 0)
        {
            result = 1;
        }
    }
    else if (cl_scan(fd, &scan, dump ? print_record : NULL, NULL) < 0)
    {
        perror("scan");
        result = 1;
    }
    else
    {
        if (print_scan(&scan) < 0)
        {
            result = 1;
        }
        else if (scan.state != CL_CLEAN)
        {
            result = 2;
        }
    }
    if (close(fd) < 0)
    {
        perror("close");
        result = 1;
    }
    if (fflush(stdout) == EOF)
    {
        perror("stdout");
        result = 1;
    }
    return result;
}
