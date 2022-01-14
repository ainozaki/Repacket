#ifndef GENERATOR_H_
#define GENERTOR_H_

#include "base/config.h"

int gen(const struct config* cfg);

// generate code of FILTER mode.
void filter_conditional_statement(const struct config* cfg, char buf[]);

#endif  // GENERATOR_H_
