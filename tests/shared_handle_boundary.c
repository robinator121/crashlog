/* Demonstrates why concurrent operations on an inherited handle are unsupported.
 * Both writers intentionally share one flock open-file description. The linker
 * barrier makes both scan the same EOF before either pwrite is allowed to run.
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "crashlog.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int ready_pipe[2];
static int release_pipe[2];

ssize_t __real_pwrite(int fd, const void *buffer, size_t count, off_t offset);

static int token(int fd, bool writing)
{
    char byte = 'x';
    ssize_t count;
    do
    {
        count = writing ? write(fd, &byte, 1) : read(fd, &byte, 1);
    } while (count < 0 && errno == EINTR);
    return count == 1 ? 0 : -1;
}

ssize_t __wrap_pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    if (token(ready_pipe[1], true) != 0 || token(release_pipe[0], false) != 0)
    {
        errno = EIO;
        return -1;
    }
    return __real_pwrite(fd, buffer, count, offset);
}

ssize_t __wrap_pwrite64(int fd, const void *buffer, size_t count, off_t offset)
{
    return __wrap_pwrite(fd, buffer, count, offset);
}

int main(void)
{
    char path[] = "/tmp/crashlog-shared-handle-XXXXXX";
    int temporary = mkstemp(path);
    if (temporary < 0)
    {
        return 1;
    }
    close(temporary);
    int fd = cl_open(path, true, false);
    if (fd < 0 || pipe(ready_pipe) != 0 || pipe(release_pipe) != 0)
    {
        unlink(path);
        return 1;
    }
    alarm(10);
    pid_t children[2];
    for (size_t i = 0; i < 2; ++i)
    {
        children[i] = fork();
        if (children[i] == 0)
        {
            alarm(5);
            _exit(cl_append(fd, "race", 4, false) == 0 ? 0 : 1);
        }
        if (children[i] < 0)
        {
            unlink(path);
            return 1;
        }
    }
    if (token(ready_pipe[0], false) != 0 || token(ready_pipe[0], false) != 0 ||
        token(release_pipe[1], true) != 0 || token(release_pipe[1], true) != 0)
    {
        unlink(path);
        return 1;
    }
    for (size_t i = 0; i < 2; ++i)
    {
        int status = 0;
        if (waitpid(children[i], &status, 0) != children[i] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            unlink(path);
            return 1;
        }
    }
    struct cl_scan_result result;
    if (cl_scan(fd, &result, NULL, NULL) != 0)
    {
        unlink(path);
        return 1;
    }
    printf("unsupported shared-handle concurrency: 2 successful appends, %llu stored record(s)\n",
           (unsigned long long)result.records);
    close(fd);
    unlink(path);
    /* A deliberate boundary observation, not a supported-concurrency test. */
    return result.state == CL_CLEAN && result.records == 1 ? 0 : 1;
}
