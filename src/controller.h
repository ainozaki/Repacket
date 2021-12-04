#ifndef CONTROLLER_H_
#define CONTROLLER_H_

#include <memory>
#include <set>
#include <string>

#include <bpf.h>

#include "bpf_wrapper.h"
#include "common/define.h"
#include "generator.h"
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
  void StartStats();

  void Stats();

  BpfWrapper bpf_wrapper_;

  std::unique_ptr<MoctokFilter> filter_;

  std::unique_ptr<Generator> generator_;

  std::unique_ptr<Map> map_;

  struct config config_;

  struct bpf_map_info map_info_ = {0};

  int map_fd_;
};

#endif  // CONTROLLER_H_
