#ifndef MAP_H_
#define MAP_H_

#include <string>
#include <vector>

extern "C" {
#include <stdint.h>
#include <libbpf.h>
}

#include "base/config.h"

struct datarec {
  uint64_t rx_packets;
  uint64_t rx_bytes;
};

struct record {
  __u64 timestamp;
  struct datarec total;
};

class MapHandler {
 public:
  MapHandler(const struct config& config);
  ~MapHandler() = default;
  MapHandler(const MapHandler&) = default;

  void Start();

  // Public for testing.
  void MapGetValueArray(__u32 key, struct datarec* value);

 private:
  int CheckMapInfo(struct bpf_map_info* exp_info, struct bpf_map_info* info);

  void StatsPoll(struct bpf_map_info* info);

  bool StatsCollect(__u32 map_type, struct record* stats_rec);

  void StatsPrint(struct record* rec,
                  struct record* prev);

	struct config config_;

  int map_fd_;
};

#endif  // MAP_H_
