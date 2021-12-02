#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include <memory>
#include <set>
#include <string>

#include <bpf.h>

#include "common/define.h"
#include "loader.h"
#include "map.h"
#include "moctok_filter.h"

class Loader;

class Controller {
 public:
  Controller(struct config& cfg);
  ~Controller() = default;
  Controller(const Controller&) = delete;

 private:
  // Collect status from map.
  void Stats();

  // Setup map.
  void MapSetup();

  // Load the BPF-ELF file.
  void StartLoading();

  std::unique_ptr<MoctokFilter> filter_;

  struct config config_;

  Map map_;

  struct bpf_map_info map_info_ = {0};

  int map_fd_;
};

#endif  // CONTROLLER_H_
