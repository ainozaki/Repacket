#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include <bpf.h>

#include "common/define.h"
#include "loader.h"
#include "map.h"

class Controller {
 public:
  Controller() = default;
  ~Controller() = default;
  Controller(const Controller&) = delete;

  // Load the BPF-ELF file and returns err code.
  void StartLoading(struct config& cfg);

  // Detach XDP program and returns err code.
  void DetachXDP(struct config& cfg);

 private:
  void Stats();

  void MapSetup();

  Loader loader_;

  Map map_;

  struct bpf_map_info map_info_ = {0};

  int map_fd_;
};

#endif  // CONTROLLER_H_
