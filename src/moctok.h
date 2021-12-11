#ifndef MOCTOK_H_
#define MOCTOK_H_

#include <memory>
#include <set>
#include <string>

#include <bpf/bpf.h>

#include "base/bpf_wrapper.h"
#include "base/define/define.h"
#include "core/generator/generator.h"
#include "core/loader/loader.h"
#include "core/loader/moctok_filter.h"
#include "core/logger/map.h"

class Loader;

class MocTok {
 public:
  MocTok(struct config& cfg);
  ~MocTok() = default;
  MocTok(const MocTok&) = delete;

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

#endif  // MOCTOK_H_
