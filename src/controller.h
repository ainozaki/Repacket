#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include <string>

#include <bpf.h>

#include "common/define.h"
#include "loader.h"
#include "map.h"

class Controller {
 public:
  Controller() = default;
  ~Controller() = default;
  Controller(const Controller&) = delete;

  void ParseCmdline(int argc, char** argv);

 private:
  // Detach XDP program.
  void DetachXDP(struct config& cfg);

  // Generate XDP program using specified yaml file.
  void GenerateXDP(std::string& file);

  // Collect status from map.
  void Stats();

  // Setup map.
  void MapSetup();

  // Load the BPF-ELF file.
  void StartLoading(struct config& cfg);

  Loader loader_;

  Map map_;

  struct bpf_map_info map_info_ = {0};

  int map_fd_;
};

#endif  // CONTROLLER_H_
