#ifndef LOADER_H_
#define LOADER_H_

#include <linux/types.h>
#include <stdbool.h>

#include "base/config.h"

// Attach "xdp-generated-kern.o" to cfg->ifindex.
// Map name is expected to be "perf-map".
int attach(struct config* cfg, int* map_fd);

// Detach xdp program.
int detach(struct config* cfg);

#endif  // LOADER_H_
