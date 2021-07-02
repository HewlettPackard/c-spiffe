#include "c-spiffe/logger/logger.h"

#include <stdio.h>
#include <stdlib.h>

const size_t MAX_LOGGER_CAP = 1 << 7;
const size_t MAX_STR_CAP = 1 << 8;
char **__str_debug, **__str_error;
int __str_debug_idx, __str_error_idx;

const char DEBUG_PREFIX[] = "[DEBUG] ";
const char ERROR_PREFIX[] = "[ERROR] ";
const size_t DEBUG_PREFIX_LEN = sizeof DEBUG_PREFIX - 1;
const size_t ERROR_PREFIX_LEN = sizeof ERROR_PREFIX - 1;

static void vfmtPush(char *const *__str, int *__str_idx, const char *fmt,
                     va_list args)
{
    // debug_fmt = "[DEBUG] " + fmt;
    string_t debug_fmt = string_new(DEBUG_PREFIX);
    debug_fmt = string_push(debug_fmt, fmt);

    // circular buffer
    char *const new_str = __str[(*__str_idx)++];
    *__str_idx %= MAX_LOGGER_CAP;
    vsnprintf(new_str, MAX_STR_CAP, debug_fmt, args);

    arrfree(debug_fmt);
}

static void push(char *const *__str, int *__str_idx, const char *str)
{
    // circular buffer
    char *const new_str = __str[(*__str_idx)++];
    *__str_idx %= MAX_LOGGER_CAP;
    strcpy(new_str, DEBUG_PREFIX);
    strncat(new_str, str, MAX_STR_CAP - DEBUG_PREFIX_LEN - 1);
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

void logger_Init(void)
{
    logger_Debug_Init();
    logger_Error_Init();
}

void logger_Debug_Init(void)
{
    __str_debug = malloc(MAX_LOGGER_CAP * sizeof __str_debug[0]);
    for(size_t i = 0; i < MAX_LOGGER_CAP; ++i) {
        __str_debug[i] = calloc(MAX_STR_CAP, sizeof __str_debug[0][0]);
    }
    __str_debug_idx = 0;
}

int logger_Debug_BufferSize(void)
{
    if(__str_debug) {
        return MAX_LOGGER_CAP;
    }

    return 0;
}

void logger_Debug_FmtPush(const char *fmt, ...)
{
    if(__str_debug && fmt) {
        va_list args;
        va_start(args, fmt);

        vfmtPush(__str_debug, &__str_debug_idx, fmt, args);

        va_end(args);
    }
}

void logger_Debug_Push(const char *str)
{
    if(__str_debug && str) {
        push(__str_debug, &__str_debug_idx, str);
    }
}

const char *logger_Debug_Back(void)
{
    if(__str_debug) {
        return back(__str_debug, __str_debug_idx);
    }

    return NULL;
}

void logger_Debug_Pop(void)
{
    if(__str_debug) {
        return pop(__str_debug, &__str_debug_idx);
    }
}

void logger_Debug_Dumpf(FILE *f)
{
    if(__str_debug && f) {
        dumpf(__str_debug, __str_debug_idx, f);
    }
}

string_t logger_Debug_Dumps(void)
{
    if(__str_debug) {
        return dumps(__str_debug, __str_debug_idx);
    }

    return NULL;
}

void logger_Error_Init(void)
{
    __str_error = malloc(MAX_LOGGER_CAP * sizeof __str_error[0]);
    for(size_t i = 0; i < MAX_LOGGER_CAP; ++i) {
        __str_error[i] = calloc(MAX_STR_CAP, sizeof __str_error[0][0]);
    }
    __str_error_idx = 0;
}

int logger_Error_BufferSize(void)
{
    if(__str_error) {
        return MAX_LOGGER_CAP;
    }

    return 0;
}

void logger_Error_FmtPush(const char *fmt, ...)
{
    if(__str_error && fmt) {
        va_list args;
        va_start(args, fmt);

        vfmtPush(__str_error, &__str_error_idx, fmt, args);

        va_end(args);
    }
}

void logger_Error_Push(const char *str)
{
    if(__str_error && str) {
        push(__str_error, &__str_error_idx, str);
    }
}

const char *logger_Error_Back(void)
{
    if(__str_error) {
        return back(__str_error, __str_error_idx);
    }

    return NULL;
}

void logger_Error_Pop(void)
{
    if(__str_error) {
        return pop(__str_error, &__str_error_idx);
    }
}

void logger_Error_Dumpf(FILE *f)
{
    if(__str_error && f) {
        dumpf(__str_error, __str_error_idx, f);
    }
}

string_t logger_Error_Dumps(void)
{
    if(__str_error) {
        return dumps(__str_error, __str_error_idx);
    }

    return NULL;
}

void logger_Cleanup(void)
{
    if(__str_debug) {
        for(size_t i = 0; i < MAX_LOGGER_CAP; ++i) {
            free(__str_debug[i]);
        }
        free(__str_debug);
    }

    if(__str_error) {
        for(size_t i = 0; i < MAX_LOGGER_CAP; ++i) {
            free(__str_error[i]);
        }
        free(__str_error);
    }
}
