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
  Map() = default;
  ~Map() = default;
  Map(const Map&) = delete;

  int FindMapFd(struct bpf_object* bpf_obj, const char* mapname);

  int CheckMapInfo(int map_fd, struct bpf_map_info* info);

  void StatsPoll(int map_fd, struct bpf_map_info* info);

 private:
  void MapGetValueArray(int fd, __u32 key, struct datarec* value);

  bool MapCollect(int fd, __u32 map_type, __u32 key, struct record* rec);

  void StatsCollect(int map_fd, __u32 map_type, struct stats_record* stats_rec);

  void StatsPrint(struct stats_record* stats_rec,
                  struct stats_record* stats_prev);
};

#endif  // MAP_H_
