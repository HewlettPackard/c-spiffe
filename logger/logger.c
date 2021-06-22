#include "logger/logger.h"
#include "utils/util.h"

#include <stdio.h>
#include <stdlib.h>

const size_t MAX_LOGGER_CAP = 256;
string_t __str_debug;

void logger_Init(void)
{
    /// TODO: init all loggers here
    arrsetcap(__str_debug, MAX_LOGGER_CAP);
}

void logger_Debugf(const char *fmt, ...)
{
    if(__str_debug) {
        // debug_fmt = "[DEBUG] " + fmt + "\n";
        string_t debug_fmt = string_new("[DEBUG] ");
        debug_fmt = string_push(debug_fmt, fmt);
        debug_fmt = string_push(debug_fmt, "\n");

        va_list args;
        va_start(args, fmt);
        vsnprintf(__str_debug, arrlenu(__str_debug), debug_fmt, &args);

        arrfree(debug_fmt);

        va_end(args);
    }
}

void logger_Cleanup(void)
{
    /// TODO: close all loggers here
    if(__file_debug) {
        fclose(__file_debug);
    }
}
