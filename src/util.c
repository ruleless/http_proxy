#include <unistd.h>
#include <sys/stat.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

void daemonize(const char *path)
{
    /* Our process ID and Session ID */
    pid_t pid, sid;
    int nullfd = open("/dev/null", O_RDWR);

    if (nullfd < 0) {
        exit(EXIT_FAILURE);
    }

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
     * we can exit the parent process. */
    if (pid > 0) {
        FILE *file = fopen(path, "w");
        if (file == NULL) {
            exit(EXIT_FAILURE);
        }

        fprintf(file, "%d", (int)pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    dup2(nullfd, STDIN_FILENO);
    dup2(nullfd, STDOUT_FILENO);
    dup2(nullfd, STDERR_FILENO);
    close(nullfd);
}

void print_stack_frames(void (*print)(const char *sym))
{
    int j, nptrs;

#define SIZE 100
    void *buffer[100];
    char **strings;

    nptrs = backtrace(buffer, SIZE);
    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }

    for (j = 0; j < nptrs; j++) {
        print(strings[j]);
    }

    free(strings);

#undef SIZE
}
