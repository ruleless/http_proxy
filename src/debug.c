#include <stdarg.h>
#include <execinfo.h>

#include "debug.h"

#define DEBUG_FILE "/tmp/debug.log"

void debug_print(const char *fmt, ...)
{
    va_list args;
	char buf[1024];
    FILE *file = fopen(DEBUG_FILE, "at");

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

    if (!file)
        return;

    fprintf(file, "%s\n", (const char *)buf);
    fclose(file);
}

void debug_print_stack()
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

    for (j = 0; j < nptrs; j++)
        debug_print("%s", strings[j]);

    free(strings);
}

#undef DEBUG_FILE
