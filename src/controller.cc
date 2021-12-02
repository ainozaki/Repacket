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
  switch (config_.mode) {
    case Mode::Generate:
      // Generate XDP program according to rules in yaml file.
      { Generator generator(config_.yaml_filepath); }
      break;
    case Mode::Load:
      // MocktokFilter loads Bpf program.
      filter_ = std::make_unique<MoctokFilter>(cfg);
      StartLoading();
      break;
    case Mode::Unload:
      // MocktokFilter unloads Bpf program.
      filter_ = std::make_unique<MoctokFilter>(cfg);
      break;
      // TODO: Handle Mode::Status.
    default:
      break;
  }
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
