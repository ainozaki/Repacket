#include "controller.h"

#include <cassert>
#include <cstdint>
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
      break;
    case Mode::Unload:
      // MocktokFilter unloads Bpf program.
      filter_ = std::make_unique<MoctokFilter>(cfg);
      break;
    case Mode::Status:
      StartStats();
      break;
    default:
      assert(false);
      break;
  }
}

// TODO: Improve Map constructor.
void Controller::StartStats() {
  // TODO: Make a constant for mapname.
  std::string map_path = "/sys/fs/bpf/" + config_.ifname + "/xdp_stats_map";
  map_fd_ = bpf_obj_get(map_path.c_str());
  if (map_fd_ < 0) {
    std::cerr << "ERR: Failed to open " << map_path << std::endl;
    return;
  }
  Stats();
}

void Controller::Stats() {
  // TODO: make map_info a member of Map
  struct bpf_map_info map_info = {0};
  int check_result = map_.CheckMapInfo(map_fd_, &map_info);
  if (check_result) {
    std::cerr << "ERR: Failed to get map info." << std::endl;
    return;
  }
  map_.StatsPoll(map_fd_, &map_info);
}
