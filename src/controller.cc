#include "controller.h"

#include <bpf.h>

#include "common/define.h"
#include "loader.h"
#include "map.h"

void Controller::Stats() {
  map_.StatsPoll(map_fd_, &map_info_);
}

void Controller::MapSetup() {
  // Check map info.
  struct bpf_map_info expect = {0};
  expect.key_size = sizeof(__u32);
  expect.value_size = sizeof(struct datarec);
  expect.max_entries = 5;
  int check_result = map_.CheckMapInfo(map_fd_, &map_info_, &expect);
  if (check_result) {
    exit(check_result);
  }

  Stats();
}

void Controller::StartLoading(struct config& cfg) {
  // Load the BPF-ELF object file and attach to an interface.
  struct bpf_object* bpf_obj = loader_.LoadAndAttach(cfg);

  map_fd_ = map_.FindMapFd(bpf_obj, "xdp_stats_map");

  // Setup map.
  MapSetup();
}

void Controller::DetachXDP(struct config& cfg) {
  loader_.Detach(cfg.ifindex, cfg.xdp_flags);
}
