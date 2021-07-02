#ifndef INCLUDE_LOGGER_LOGGER_H
#define INCLUDE_LOGGER_LOGGER_H

#include "c-spiffe/utils/util.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Init all loggers.
 */
void logger_Init(void);

/**
 * Init Debug logger.
 */
void logger_Debug_Init(void);

/**
 * Get Debug logger size. The logger is implemented as a cyclic buffer,
 * thus having limited capacity.
 */
int logger_Debug_BufferSize(void);

/**
 * Pushes message into Debug logger with printf format.
 */
void logger_Debug_FmtPush(const char *fmt, ...);

/**
 * Pushes message into Debug logger.
 */
void logger_Debug_Push(const char *str);

/**
 * Returns the logger last message. The value should be used or stored before
 * using any other logger operation.
 */
const char *logger_Debug_Back(void);

/**
 * Pops last Debug logger message.
 */
void logger_Debug_Pop(void);

/**
 * Dumps the stored logs on the file f, separating the messages by '\n'
 * character.
 */
void logger_Debug_Dumpf(FILE *f);

/**
 * Dumps the stored logs on a new string, separating the messages by '\n'
 * character. The string should be freed using arrfree function.
 */
string_t logger_Debug_Dumps(void);

/**
 * Init Error logger.
 */
void logger_Error_Init(void);

/**
 * Get Error logger size. The logger is implemented as a cyclic buffer,
 * thus having limited capacity.
 */
int logger_Error_BufferSize(void);

/**
 * Pushes message into Error logger with printf format.
 */
void logger_Error_FmtPush(const char *fmt, ...);

/**
 * Pushes message into Error logger.
 */
void logger_Error_Push(const char *str);

/**
 * Returns the logger last message. The value should be used or stored before
 * using any other logger operation.
 */
const char *logger_Error_Back(void);

/**
 * Pops last Error logger message.
 */
void logger_Error_Pop(void);

/**
 * Dumps the stored logs on the file f, separating the messages by '\n'
 * character.
 */
void logger_Error_Dumpf(FILE *f);

/**
 * Dumps the stored logs on a new string, separating the messages by '\n'
 * character. The string should be freed using arrfree function.
 */
string_t logger_Error_Dumps(void);

/**
 * Cleans up all loggers. Should be called when the logger functions will no
 * longer be used.
 */
void logger_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif
