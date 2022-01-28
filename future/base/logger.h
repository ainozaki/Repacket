#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>

#define DEBUG_ON

#ifdef DEBUG_ON
#define LOG_DEBUG(...)                                                         \
  printf("[DEBUG][%s][%d][%s] ", __FILE__, __LINE__, __func__),                \
      printf(__VA_ARGS__)
#define LOG_ERROR(...)                                                         \
  printf("\x1b[31m[ERROR][%s][%d][%s]\x1b[39m ", __FILE__, __LINE__,           \
         __func__),                                                            \
      printf(__VA_ARGS__)
#define LOG_INFO(...)                                                          \
  printf("\x1b[36m[INFO][%s][%d][%s]\x1b[39m ", __FILE__, __LINE__, __func__), \
      printf(__VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

#endif // LOGGER_H_
