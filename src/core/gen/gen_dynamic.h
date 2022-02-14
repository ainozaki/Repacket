#ifndef GEN_DYNAMIC_H_
#define GEN_DYNAMIC_H_

#include <string>

#include "base/config.h"

std::string FilteringStatement(const struct config& cfg);
std::string RewriteStatement(const struct config& cfg);

#endif
