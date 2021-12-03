#ifndef MAP_H_
#define MAP_H_

#include <libbpf.h>

#include "utils.h"

#include "common/define.h"

struct record {
  __u64 timestamp;
  struct datarec total;
};

struct stats_record {
  struct record stats[2];
};

class Map {
 public:
  Map(int map_fd);
  ~Map() = default;
  Map(const Map&) = delete;

  static int FindMapFd(struct bpf_object* bpf_obj, const char* mapname);

  int CheckMapInfo(struct bpf_map_info* info);

  void StatsPoll(struct bpf_map_info* info);

 private:
  void MapGetValueArray(__u32 key, struct datarec* value);

  bool MapCollect(__u32 map_type, __u32 key, struct record* rec);

  void StatsCollect(__u32 map_type, struct stats_record* stats_rec);

  void StatsPrint(struct stats_record* stats_rec,
                  struct stats_record* stats_prev);

  int map_fd_;
};

#endif  // MAP_H_
