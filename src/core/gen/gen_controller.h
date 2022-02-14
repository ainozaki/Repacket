#ifndef GEN_CONTROLLER_H_
#define GEN_CONTROLLER_H_

#include <memory>
#include <string>

#include "base/config.h"

int Gen(const struct config& cfg);
int Compile();

// generate code in each mode.
void filter_conditional_statement(const struct config* cfg, char buf[]);
void rewrite_statement(const struct config* cfg, char buf[], char buf2[]);

#endif  // GEN_CONTROLLER_H_
