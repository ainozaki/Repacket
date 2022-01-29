#ifndef GENERATOR_H_
#define GENERATOR_H_

#include <memory>
#include <string>

#include "base/config.h"

int Gen(const struct config& cfg);
int Compile();

// generate code in each mode.
void filter_conditional_statement(const struct config* cfg, char buf[]);
void rewrite_statement(const struct config* cfg, char buf[], char buf2[]);

std::string FilteringStatement(const struct config& cfg);
#endif  // GENERATOR_H_
