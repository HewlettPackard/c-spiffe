#ifndef INCLUDE_LOGGER_LOGGER_H
#define INCLUDE_LOGGER_LOGGER_H

#include "c-spiffe/utils/util.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { LOGGER_DEBUG = 0, LOGGER_ERROR, LOGGER_WARNING, LOGGER_LEN };

/**
 * Init all loggers.
 */
void logger_InitAll(void);

/**
 * Init particular logger.
 */
void logger_Init(int type);

/**
 * Get specified logger size. The logger is implemented as a cyclic buffer,
 * thus having limited capacity.
 */
int logger_BufferSize(int type);

/**
 * Pushes message into the specified logger with printf format.
 */
void logger_FmtPush(int type, const char *fmt, ...);

/**
 * Pushes message into the specified logger.
 */
void logger_Push(int type, const char *str);

/**
 * Returns the logger last message. The value should be used or stored before
 * using any other logger operation.
 */
const char *logger_Back(int type);

/**
 * Pops speficied logger last message.
 */
void logger_Pop(int type);

/**
 * Dumps the stored logs on the file f, separating the messages by '\n'
 * character.
 */
void logger_Dumpf(int type, FILE *f);

/**
 * Dumps the stored logs on a new string, separating the messages by '\n'
 * character. The string should be freed using arrfree function.
 */
string_t logger_Dumps(int type);

/**
 * Cleans up a specific logger. Should be called when the logger respective
 * functions will no longer be used.
 */
void logger_Cleanup(int type);

/**
 * Cleans up all logger. Should be called when the logger functions will no
 * longer be used.
 */
void logger_CleanupAll(void);

#ifdef __cplusplus
}
#endif

#endif
