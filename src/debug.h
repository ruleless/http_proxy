#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif


# define DEBUG_PRINT(fmt, ...)                                     \
    do { debug_print("[%s:%d][%ld][%s]" fmt, __FILE__, __LINE__, (long)getpid(), __FUNCTION__, ##__VA_ARGS__); } while (0)

# define DEBUG_PRINT_STACK()                                       \
    do { DEBUG_PRINT("print stackframe"); debug_print_stack(); } while (0)


/*
 * 打印调试日志
 */
void debug_print(const char *fmt, ...);

/*
 * 打印堆栈
 */
void debug_print_stack();

#ifdef __cplusplus
}
#endif

#endif /* __DEBUG_H__ */
