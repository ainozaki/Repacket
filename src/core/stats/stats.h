#ifndef STATS_H_
#define STATS_H_

#include <memory>
#include <string>

#include "base/bpf_wrapper.h"
#include "core/stats/map_handler.h"

class Stats {
 public:
  Stats(const std::string& ifname);
  ~Stats() = default;
  Stats(const Stats&) = delete;

  // An interface function to get stats using map.
  int Start();

 private:
  std::unique_ptr<MapHandler> map_handler_;

  std::unique_ptr<BpfWrapper> bpf_wrapper_;

  std::string map_path_;

  std::string ifname_;

  int map_fd_;
};

#endif  // STATS_H_
