#ifndef INCLUDE_LOGGER_LOGGER_H
#define INCLUDE_LOGGER_LOGGER_H

#include "utils/util.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void logger_InitLoggers(void);

void loffer_Debug_Init(void);

void logger_Debug_FmtPush(const char *fmt, ...);

void loffer_Debug_Push(const char *str);

const char *logger_Debug_Back(void);

const char *logger_Debug_Pop(void);

void logger_Debug_Dumpf(FILE *f);

string_t logger_Debug_Dumps(void);

void logger_Info_Init();

void logger_Warn_Init();

void logger_Error_Init();

void logger_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
