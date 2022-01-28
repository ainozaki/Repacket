#ifndef LOADER_H_
#define LOADER_H_

#include <memory>

#include "base/config.h"

// Attach "xdp-generated-kern.o" to cfg->ifindex.
// Map name is expected to be "perf-map".
int Attach(std::shared_ptr<struct config> cfg, std::shared_ptr<int> map_fd);

// Detach xdp program.
int Detach(std::shared_ptr<struct config> cfg);

#endif  // LOADER_H_
