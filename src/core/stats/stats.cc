#include "core/stats/stats.h"

#include <iostream>
#include <memory>
#include <string>

#include "base/bpf_wrapper.h"
#include "base/define/constant.h"
#include "base/define/define.h"
#include "base/yaml_handler.h"
#include "core/stats/map_handler.h"

Stats::Stats(const std::string& ifname) : ifname_(ifname) {
  // Get the file discripter of pinned map.
  map_path_ = "/sys/fs/bpf/" + ifname_ + "/" + kMapName;
  map_fd_ = bpf::GetPinnedObjFd(map_path_.c_str());
  if (map_fd_ < 0) {
    std::cerr << "ERR: Failed to open " << map_path_ << std::endl;
    return;
  }

  map_handler_ = std::make_unique<MapHandler>(map_fd_);
}

void Stats::Start() {
  map_handler_->Start();
}

datarec Stats::GetMapValueForTesting(__u32 key) {
  struct datarec value;
  map_handler_->MapGetValueArray(key, &value);
  return value;
}
