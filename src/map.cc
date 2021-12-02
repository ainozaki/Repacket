#include "map.h"

#include <bpf.h>
#include <libbpf.h>

#include <iostream>

#include "common/define.h"
#include "utils.h"

int Map::FindMapFd(struct bpf_object* bpf_obj, const char* mapname) {
  // Find the map object by name.
  struct bpf_map* map = bpf_object__find_map_by_name(bpf_obj, mapname);
  if (!map) {
    std::cout << "ERR: find map failed." << std::endl;
    exit(EXIT_FAIL_MAP);
  }

  // Find the correspond FD.
  int map_fd = bpf_map__fd(map);
  return map_fd;
}

int Map::CheckMapInfo(int map_fd, struct bpf_map_info* info) {
  std::cout << "Checking map information..." << std::endl;
  __u32 info_len = sizeof(*info);
  int err;

  struct bpf_map_info exp = {0};
  exp.key_size = sizeof(__u32);
  exp.value_size = sizeof(struct datarec);
  exp.max_entries = 5;

  if (map_fd < 0)
    return EXIT_FAIL;

  // BPF-info via bpf-syscall
  err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
  if (err) {
    std::cout << "ERR: Cannot get info." << std::endl;
    return EXIT_FAIL_BPF;
  }
  if (exp.key_size && exp.key_size != info->key_size) {
    std::cout << "ERR: Unexpected size." << std::endl;
    return EXIT_FAIL;
  }
  if (exp.value_size && exp.value_size != info->value_size) {
    std::cout << "ERR: Unexpected value size." << std::endl;
    return EXIT_FAIL;
  }
  if (exp.max_entries && exp.max_entries != info->max_entries) {
    std::cout << "ERR: Unexpected max_entries value." << std::endl;
    return EXIT_FAIL;
  }
  if (exp.type && exp.type != info->type) {
    std::cout << "ERR: Unexpected type." << std::endl;
    return EXIT_FAIL;
  }
  return 0;
}

void Map::MapGetValueArray(int fd, __u32 key, struct datarec* value) {
  if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
    std::cout << "ERR: bpf_map_lookup_elem" << std::endl;
  }
}

bool Map::MapCollect(int fd, __u32 map_type, __u32 key, struct record* rec) {
  struct datarec value;
  rec->timestamp = gettime();
  switch (map_type) {
    case BPF_MAP_TYPE_ARRAY:
      MapGetValueArray(fd, key, &value);
      break;
    default:
      std::cout << "Unknown map type." << std::endl;
      return false;
      break;
  }
  rec->total.rx_packets = value.rx_packets;
  rec->total.rx_bytes = value.rx_bytes;
  return true;
}

void Map::StatsCollect(int map_fd,
                       __u32 map_type,
                       struct stats_record* stats_rec) {
  __u32 key_pass = XDP_PASS;
  __u32 key_drop = XDP_DROP;

  MapCollect(map_fd, map_type, key_pass, &stats_rec->stats[0]);
  MapCollect(map_fd, map_type, key_drop, &stats_rec->stats[1]);
}

void Map::StatsPrint(struct stats_record* stats_rec,
                     struct stats_record* stats_prev) {
  struct record *rec, *prev;
  double period;
  __u64 packets, bytes;
  double pps, bps;

  printf(
      "----------------------------------------------------------------------"
      "-------------------------------------\n");
  for (int i = 0; i < 2; i++) {
    const char* fmt =
        "%-12s %'11lld pkts (%'12.0f pps)"
        " %'11lld bytes (%'12.0f bps)"
        " period:%f\n";

    const char* action;
    switch (i) {
      case 0:
        action = "XDP_PASS";
        break;
      case 1:
        action = "XDP_DROP";
        break;
    }
    rec = &stats_rec->stats[i];
    prev = &stats_prev->stats[i];

    period = calc_period(rec, prev);
    if (period == 0)
      return;

    packets = rec->total.rx_packets - prev->total.rx_packets;
    pps = packets / period;

    bytes = rec->total.rx_bytes - prev->total.rx_bytes;
    bps = bytes / period;

    printf(fmt, action, rec->total.rx_packets, pps, rec->total.rx_bytes, bps,
           period);
  }
}

void Map::StatsPoll(int map_fd, struct bpf_map_info* info) {
  std::cout << "Polling stats..." << std::endl;
  struct stats_record prev, record = {0};

  // Initial reading
  StatsCollect(map_fd, info->type, &record);
  usleep(1000000 / 4);

  while (1) {
    prev = record;
    StatsCollect(map_fd, info->type, &record);
    StatsPrint(&record, &prev);
    sleep(1);
  }
}
