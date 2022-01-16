#ifndef GENERATOR_H_
#define GENERTOR_H_

#include "base/config.h"

int gen(const struct config* cfg);

// generate code in each mode.
void filter_conditional_statement(const struct config* cfg, char buf[]);
void rewrite_statement(const struct config* cfg, char buf[], char buf2[]);

#endif  // GENERATOR_H_
