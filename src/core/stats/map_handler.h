#ifndef MAP_H_
#define MAP_H_

#include <string>

#include <libbpf.h>

#include "base/bpf_wrapper.h"
#include "base/define/define.h"
#include "base/utils.h"

struct record {
  __u64 timestamp;
  struct datarec total;
};

struct stats_record {
  struct record stats[2];
};

class MapHandler {
 public:
  MapHandler(int map_fd, int filter_size);
  ~MapHandler() = default;
  MapHandler(const MapHandler&) = delete;

  void Start();

 private:
  int CheckMapInfo(struct bpf_map_info* exp_info, struct bpf_map_info* info);

  void StatsPoll(struct bpf_map_info* info);

  void StatsCollect(__u32 map_type, struct stats_record* stats_rec);

  bool MapCollect(__u32 map_type, __u32 key, struct record* rec);

  void MapGetValueArray(__u32 key, struct datarec* value);

  void StatsPrint(struct stats_record* stats_rec,
                  struct stats_record* stats_prev);

  BpfWrapper bpf_wrapper_;

  int map_fd_;

  int filter_size_;

  std::string ifname_;

  std::string map_path_;
};

#endif  // MAP_H_
