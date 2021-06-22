#ifndef INCLUDE_LOGGER_LOGGER_H
#define INCLUDE_LOGGER_LOGGER_H

void logger_InitLogger(void);

void logger_Debugf();

void logger_Infof();

void logger_Warnf();

void logger_Errorf();

void logger_Cleanup(void);

#endif