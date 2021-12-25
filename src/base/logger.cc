#include <base/logger.h>

#include <iostream>
#include <string>

#include "base/define/define.h"

Logger::Logger(const LogLevel& level) : level_(level) {}

void Logger::Info(const std::string& message) {
  // TODO: support variable argument.
  // TODO: stop using const std::string&.
  if (level_ != LogLevel::Info) {
    return;
  }
  std::cout << "[Info] " << message << std::endl;
}

void Logger::Error(const std::string& message) {
  if (level_ != LogLevel::Error) {
    return;
  }
  std::cout << "[Error] " << message << std::endl;
}
