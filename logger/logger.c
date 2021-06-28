#include "logger/logger.h"
#include "utils/util.h"

#include <stdio.h>
#include <stdlib.h>

const size_t MAX_LOGGER_CAP = 1 << 7;
const size_t MAX_STR_CAP = 1 << 8;
string_arr_t __str_debug;

const char *DEBUG_PREFIX = "[DEBUG] ";

void logger_Init(void)
{
    /// TODO: init all loggers here
    arrsetcap(__str_debug, MAX_LOGGER_CAP);
}

void logger_Debug_FmtPush(const char *fmt, ...)
{
    if(__str_debug && fmt) {
        // debug_fmt = "[DEBUG] " + fmt + "\n";
        string_t debug_fmt = string_new(DEBUG_PREFIX);
        debug_fmt = string_push(debug_fmt, fmt);
        debug_fmt = string_push(debug_fmt, "\n");

        va_list args;
        va_start(args, fmt);

        string_t new_str = NULL;
        arrsetcap(new_str, MAX_STR_CAP);
        vsnprintf(new_str, arrcap(new_str), debug_fmt, &args);
        arrsetlen(new_str, strlen(new_str) + 1);
        arrpush(__str_debug, new_str);

        arrfree(debug_fmt);

        va_end(args);
    }
}

void logger_Debug_Push(const char *str)
{
    if(__str_debug && str) {
        string_t new_str = string_new(DEBUG_PREFIX);
        /// TODO: set max capacity?
        new_str = string_push(new_str, str);
        new_str = string_push(new_str, "\n");

        arrpush(__str_debug, new_str);
    }
}

const char *logger_Debug_Back(void)
{
    const size_t len = arrlenu(__str_debug);
    if(len > 0) {
        return __str_debug[len - 1];
    }

    return NULL;
}

const char *logger_Debug_Pop(void)
{
    if(arrlenu(__str_debug) > 0) {
        return arrpop(__str_debug);
    }

    return NULL;
}

const char **logger_Debug_Traceback(bool clean)
{
    // dummy
    return NULL;
}

void logger_Debug_Dumpf(FILE *f)
{
    // dummy
}

string_t logger_Debug_Dumps(void)
{
    // dummy
    return NULL;
}

void logger_Cleanup(void)
{
    /// TODO: close all loggers here
    util_string_arr_t_Free(__str_debug);
    
}
