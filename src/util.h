#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

void daemonize(const char *path);

void print_stack_frames(void (*print)(const char *sym));

#ifdef __cplusplus
}
#endif

#endif /* __UTIL_H__ */
