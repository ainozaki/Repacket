#ifndef LOADER_H_
#define LOADER_H_

extern "C" {
#include <libbpf.h>
}

#include "base/config.h"
#include "core/xdp/map_handler.h"
#include "core/xdp/perf_handler.h"

class Loader {
 public:
  Loader(const struct config& cfg);
  ~Loader() = default;
  Loader(const Loader&) = default;

  // Interface function to start loading.
  int Start();

  // Detach xdp program.
  int Detach();

 private:
  // Attach "xdp-generated-kern.o" to cfg->ifindex.
  // Map name is expected to be "perf-map".
  int Attach();

  int PinMaps();

  struct config config_;

  int map_fd_;

  std::string map_name_;

  struct bpf_object* bpf_obj_;

  std::optional<PerfHandler> perf_handler_;

  std::optional<MapHandler> map_handler_;
};

#endif  // LOADER_H_
