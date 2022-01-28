#ifndef PARSE_CMDLINE_H_
#define PARSE_CMDLINE_H_

#include <memory>

#include "base/config.h"

int parse_cmdline(int argc, char* argv[], std::shared_ptr<struct config> cfg);

#endif // PARSE_CMDLINE_H_
