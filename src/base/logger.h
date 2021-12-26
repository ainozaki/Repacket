#ifndef LOGGER_H_
#define LOGGER_H_

#include "base/define/define.h"

class Logger {
 public:
  Logger() = default;
  ~Logger() = default;
  Logger(const Logger&) = delete;

  static void Write(const LogLevel& level,
                    const char* file,
                    const char* func,
                    const int line,
                    const char* message,
                    ...);
};

#define LOG_INFO(...) \
  Logger::Write(LogLevel::Info, __FILE__, __func__, __LINE__, __VA_ARGS__);
#define LOG_ERROR(...) \
  Logger::Write(LogLevel::Error, __FILE__, __func__, __LINE__, __VA_ARGS__);

#endif  // LOGGER_H_
