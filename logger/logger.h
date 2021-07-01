#ifndef INCLUDE_LOGGER_LOGGER_H
#define INCLUDE_LOGGER_LOGGER_H

#include "utils/util.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void logger_Init(void);

void logger_Debug_Init(void);

int logger_Debug_BufferSize(void);

void logger_Debug_FmtPush(const char *fmt, ...);

void logger_Debug_Push(const char *str);

const char *logger_Debug_Back(void);

void logger_Debug_Pop(void);

void logger_Debug_Dumpf(FILE *f);

string_t logger_Debug_Dumps(void);

void logger_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
