#include "core/stats/stats.h"

#include <iostream>
#include <memory>
#include <string>

#include "base/bpf_wrapper.h"
#include "base/define/constant.h"
#include "base/define/define.h"
#include "core/stats/map_handler.h"

Stats::Stats(const std::string& ifname)
    : bpf_wrapper_(std::make_unique<BpfWrapper>()), ifname_(ifname) {
  map_path_ = "/sys/fs/bpf/" + ifname_ + "/" + kMapName;
  map_fd_ = bpf_wrapper_->BpfGetPinnedObjFd(map_path_.c_str());
  if (map_fd_ < 0) {
    std::cerr << "ERR: Failed to open " << map_path_ << std::endl;
    exit(EXIT_FAIL);
  }
  map_handler_ = std::make_unique<MapHandler>(map_fd_);
}

int Stats::Start() {
  map_handler_->Start();
  return 0;
}
