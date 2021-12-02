#include "controller.h"

#include <cassert>
#include <memory>
#include <string>

#include <bpf.h>
#include <cmdline.h>

#include "common/define.h"
#include "generator.h"
#include "loader.h"
#include "map.h"
#include "moctok_filter.h"

Controller::Controller(struct config& cfg) : config_(cfg) {
  if (config_.generate) {
    // Generate XDP program according to rules in yaml file.
    Generator generator(config_.yaml_filepath);
    return;
  }

  // MocktokFilter loads/unloads Bpf program.
  filter_ = std::make_unique<MoctokFilter>(cfg);
  if (config_.unload) {
    return;
  }

  StartLoading();
}

void Controller::StartLoading() {
  map_fd_ = map_.FindMapFd(filter_->bpf_obj(), "xdp_stats_map");

  // Setup map.
  MapSetup();

  // Start collecting stats.
  Stats();
}

void Controller::Stats() {
  map_.StatsPoll(map_fd_, &map_info_);
}

void Controller::MapSetup() {
  // Check map info.
  int check_result = map_.CheckMapInfo(map_fd_, &map_info_);
  if (check_result) {
    exit(check_result);
  }
}
