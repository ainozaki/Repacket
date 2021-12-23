#ifndef STATS_H_
#define STATS_H_

#include <memory>
#include <string>
#include <vector>

#include "core/stats/map_handler.h"

class Stats {
 public:
  Stats(const std::string& ifname, const std::string& yaml_filepath);
  ~Stats() = default;
  Stats(const Stats&) = delete;

  // An interface function to get stats using map.
  void Start();

  // Helper function to get value from map for testing.
  datarec GetMapValueForTesting(__u32 key);

 private:
  std::unique_ptr<MapHandler> map_handler_;

  std::string map_path_;

  std::string ifname_;

  int map_fd_;
};

#endif  // STATS_H_
