#ifndef __THREAD_ENV_H__
#define __THREAD_ENV_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

int set_thread_env(const char *key, const char *val);

const char *get_thread_env(const char *key);

void clear_thread_env();

#ifdef __cplusplus
}
#endif

#endif /* __THREAD_ENV_H__ */
