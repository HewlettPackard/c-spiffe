#include "c-spiffe/logger/logger.h"

#include <stdio.h>
#include <stdlib.h>

const size_t MAX_LOGGER_CAP = 1 << 7;
const size_t MAX_STR_CAP = 1 << 8;

const char DEBUG_PREFIX[] = "[DEBUG] ";
const char ERROR_PREFIX[] = "[ERROR] ";
const char WARNING_PREFIX[] = "[WARNING] ";

char **__str[LOGGER_LEN] = {};
int __str_idx[LOGGER_LEN];
const char *LOGGER_PREFIX[] = { DEBUG_PREFIX, ERROR_PREFIX, WARNING_PREFIX };
const size_t LOGGER_PREFIX_LEN[]
    = { sizeof DEBUG_PREFIX - 1, sizeof ERROR_PREFIX - 1,
        sizeof WARNING_PREFIX - 1 };

static char **init(int *__str_idx)
{
    char **alloc_str = malloc(MAX_LOGGER_CAP * sizeof alloc_str[0]);
    for(size_t i = 0; i < MAX_LOGGER_CAP; ++i) {
        alloc_str[i] = calloc(MAX_STR_CAP, sizeof alloc_str[0][0]);
    }
    *__str_idx = 0;

    return alloc_str;
}

static void vfmtPush(char *const *__str, int *__str_idx, const char *prefix,
                     const char *fmt, va_list args)
{
    // logger_fmt = prefix + fmt;
    string_t logger_fmt = string_new(prefix);
    logger_fmt = string_push(logger_fmt, fmt);

    // circular buffer
    char *const new_str = __str[(*__str_idx)++];
    *__str_idx %= MAX_LOGGER_CAP;
    vsnprintf(new_str, MAX_STR_CAP, logger_fmt, args);

    arrfree(logger_fmt);
}

static void push(char *const *__str, int *__str_idx, const char *prefix,
                 const size_t prefix_len, const char *str)
{
    // circular buffer
    char *const new_str = __str[(*__str_idx)++];
    *__str_idx %= MAX_LOGGER_CAP;
    strcpy(new_str, prefix);
    strncat(new_str, str, MAX_STR_CAP - prefix_len - 1);
}

static const char *back(char *const *__str, const int __str_idx)
{
    const char *rot_str;
    if(__str_idx > 0) {
        return __str[__str_idx - 1];
    } else if(!empty_str(rot_str = __str[MAX_LOGGER_CAP - 1])) {
        // if buffer is full, rotate
        return rot_str;
    }

    return NULL;
}

static void pop(char *const *__str, int *__str_idx)
{
    if(*__str_idx > 0) {
        __str[--(*__str_idx)][0] = 0;
        if(*__str_idx > 0) {
            if(empty_str(__str[*__str_idx - 1])) {
                // reset stack
                *__str_idx = 0;
            }
        }
    } else if(!empty_str(__str[MAX_LOGGER_CAP - 1])) {
        // if buffer is full, rotate
        __str[MAX_LOGGER_CAP - 1][0] = 0;
        *__str_idx = MAX_LOGGER_CAP - 1;
    }
}

static void dumpf(char *const *__str, const int __str_idx, FILE *f)
{
    if(!empty_str(__str[__str_idx])) {
        // if buffer is full, write till rotation
        for(size_t i = __str_idx; i < MAX_LOGGER_CAP; ++i) {
            fprintf(f, "%s\n", __str[i]);
        }
    }

    for(size_t i = 0; i < __str_idx; ++i) {
        fprintf(f, "%s\n", __str[i]);
    }
}

static string_t dumps(char *const *__str, const int __str_idx)
{
    string_t res_str = string_new("");

    if(!empty_str(__str[__str_idx])) {
        // if buffer is full, write till rotation
        for(size_t i = __str_idx; i < MAX_LOGGER_CAP; ++i) {
            res_str = string_push(res_str, __str[i]);
            res_str = string_push(res_str, "\n");
        }
    }

    for(size_t i = 0; i < __str_idx; ++i) {
        res_str = string_push(res_str, __str[i]);
        res_str = string_push(res_str, "\n");
    }

    return res_str;
}

static void cleanup(char **__str)
{
    for(size_t i = 0; i < MAX_LOGGER_CAP; ++i) {
        free(__str[i]);
    }
    free(__str);
}

void logger_InitAll(void)
{
    for(int i = 0; i < LOGGER_LEN; ++i) {
        logger_Init(i);
    }
}

void logger_Init(int type) { __str[type] = init(&__str_idx[type]); }

int logger_BufferSize(int type)
{
    if(__str[type]) {
        return MAX_LOGGER_CAP;
    }

    return 0;
}

void logger_FmtPush(int type, const char *fmt, ...)
{
    if(__str[type] && fmt) {
        va_list args;
        va_start(args, fmt);

        vfmtPush(__str[type], &__str_idx[type], LOGGER_PREFIX[type], fmt,
                 args);

        va_end(args);
    }
}

void logger_Push(int type, const char *str)
{
    if(__str[type] && str) {
        push(__str[type], &__str_idx[type], LOGGER_PREFIX[type],
             LOGGER_PREFIX_LEN[type], str);
    }
}

const char *logger_Back(int type)
{
    if(__str[type]) {
        return back(__str[type], __str_idx[type]);
    }

    return NULL;
}

void logger_Pop(int type)
{
    if(__str[type]) {
        return pop(__str[type], &__str_idx[type]);
    }
}

void logger_Dumpf(int type, FILE *f)
{
    if(__str[type] && f) {
        dumpf(__str[type], __str_idx[type], f);
    }
}

string_t logger_Dumps(int type)
{
    if(__str[type]) {
        return dumps(__str[type], __str_idx[type]);
    }

    return NULL;
}

void logger_Cleanup(int type)
{
    if(__str[type]) {
        cleanup(__str[type]);
    }
}

void logger_CleanupAll(void)
{
    for(int i = 0; i < LOGGER_LEN; ++i) {
        logger_Cleanup(i);
    }
}
