#ifndef PARSE_REWRITE_OPTION_H_
#define PARSE_REWRITE_OPTION_H_

#include <string>

#include "base/config.h"

int ParseRewriteOption(const std::string& key,
                       const std::string& value,
                       struct filter& filt,
                       struct config& cfg);

#endif  // PARSE_REWRITE_OPTION_H_
