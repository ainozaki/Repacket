#ifndef LOADER_H_
#define LOADER_H_

#include "base/config.h"

// Attach "xdp-generated-kern.o" to cfg->ifindex.
// Map name is expected to be "perf-map".
int Attach(const struct config& cfg, int& map_fd);

// Detach xdp program.
int Detach(const struct config& cfg);

#endif  // LOADER_H_
