#include "utils.h"

#include <iostream>

#include <time.h>

#include "base/define/define.h"

__u64 gettime() {
  struct timespec t;
  int res;
  res = clock_gettime(CLOCK_MONOTONIC, &t);
  if (res < 0) {
    std::cerr << "ERR: gettime. " << std::endl;
    exit(EXIT_FAIL);
  }
  return (__u64)t.tv_sec * 1000000000 + t.tv_nsec;
}

double calc_period(struct record* rec, struct record* prev) {
  double period_ = 0;
  __u64 period = 0;
  period = rec->timestamp - prev->timestamp;
  if (period > 0) {
    period_ = ((double)period / 1000000000);
  }
  return period_;
}

std::string ConvertActionToString(const Action action) {
  switch (action) {
    case Action::Pass:
      return "PASS";
    case Action::Drop:
      return "DROP";
    default:
      std::cerr << "ERR: no supported Action type" << std::endl;
      return "Unknown";
  }
}
