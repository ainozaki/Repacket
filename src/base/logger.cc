#include <base/logger.h>

#include <cassert>
#include <iostream>
#include <string>

#include <stdarg.h>

#include "base/define/define.h"

namespace {

constexpr const char* Reset = "\x1b[0m";
constexpr const char* Red = "\x1b[31m";
constexpr const char* Green = "\x1b[32m";
constexpr const char* Yellow = "\x1b[33m";
constexpr const char* Magenta = "\x1b[35m";
constexpr const char* Cyan = "\x1b[36m";

std::string LogLevelToString(const LogLevel& level) {
  switch (level) {
    case LogLevel::Info:
      return "[ INFO ]";
    case LogLevel::Error:
      return "[ ERROR ]";
    case LogLevel::Debug:
      return "[ DEBUG ]";
  }
  assert(false);
  return "";
}

}  // namespace

// static
void Logger::Write(const LogLevel& level,
                   const char* file,
                   const char* func,
                   const int line,
                   const char* format,
                   ...) {
  char message[512] = {0};
  va_list args;
  va_start(args, format);
  vsprintf(message, format, args);
  va_end(args);
  if (level == LogLevel::Info) {
    std::cout << Cyan << LogLevelToString(level) << Reset << "[" << file << "]"
              << "[" << func << "]"
              << "[" << line << "] " << Cyan << message << Reset << std::endl;
  } else if (level == LogLevel::Error) {
    std::cerr << Red << LogLevelToString(level) << Reset << "[" << file << "]"
              << "[" << func << "]"
              << "[" << line << "] " << Red << message << Reset << std::endl;
  }
}
