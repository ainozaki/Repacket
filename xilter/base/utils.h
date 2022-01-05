#ifndef UTILS_H_
#define UTILS_H_

#include <unistd.h>
#include <string>

// TODO: /base dir shouldn't include any upper directory.
#include "core/stats/map_handler.h"

__u64 gettime();

double calc_period(struct record* rec, struct record* prev);

// Convert enum class Action to String.
std::string ConvertActionToString(const Action action);

#endif  // UTILS_H_
