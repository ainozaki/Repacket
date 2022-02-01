#ifndef PARSE_CMDLINE_H_
#define PARSE_CMDLINE_H_

#include <string>

#include "base/config.h"

int ParseCmdline(int argc, std::string argv[], struct config& cfg);
int ParseCmdline(int argc, char* argv[], struct config& cfg);

#endif  // PARSE_CMDLINE_H_
