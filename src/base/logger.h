#ifndef LOGGER_H_
#define LOGGER_H_

#include <string>

#include "base/define/define.h"

class Logger {
 public:
  Logger(const LogLevel& level);
  ~Logger() = default;
  Logger(const Logger&) = delete;

  void Info(const std::string& message);
  void Error(const std::string& message);

 private:
  LogLevel level_;
};

#endif  // LOGGER_H_
