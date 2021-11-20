#ifndef UTILS_H_
#define UTILS_H_

#include <unistd.h>

#include "map.h"

__u64 gettime();

double calc_period(struct record* rec, struct record* prev);

#endif  // UTILS_H_
