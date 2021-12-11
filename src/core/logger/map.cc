#include "map.h"

#include <bpf.h>
#include <libbpf.h>

#include <cassert>
#include <iostream>

#include "base/bpf_wrapper.h"
#include "base/define/constant.h"
#include "base/define/define.h"
#include "base/utils.h"

Map::Map(const std::string& ifname) : ifname_(ifname) {
  map_path_ = "/sys/fs/bpf/" + ifname_ + "/" + kMapName;
  map_fd_ = bpf_wrapper_.BpfGetPinnedObjFd(map_path_.c_str());
  if (map_fd_ < 0) {
    std::cerr << "ERR: Failed to open " << map_path_ << std::endl;
    exit(EXIT_FAIL);
  }
}

void Map::Stats() {
  // TODO: make map_info a member of Map
  struct bpf_map_info exp_info, info;
  exp_info.key_size = sizeof(__u32);
  exp_info.value_size = sizeof(struct datarec);
  // TODO: decide max_entries dynamically.
  exp_info.max_entries = 5;
  exp_info.type = BPF_MAP_TYPE_ARRAY;

  int check_result = CheckMapInfo(&exp_info, &info);
  if (check_result) {
    std::cerr << "ERR: Failed to get map info." << std::endl;
    return;
  }

  StatsPoll(&info);
}

int Map::CheckMapInfo(struct bpf_map_info* exp_info,
                      struct bpf_map_info* info) {
  assert(map_fd_ >= 0);

  int err;
  // BPF-info via bpf-syscall
  err = bpf_wrapper_.BpfGetMapInfoByFd(map_fd_, info);
  if (err) {
    std::cerr << "ERR: Cannot get info." << std::endl;
    return EXIT_FAIL_BPF;
  }
  if (exp_info->key_size && exp_info->key_size != info->key_size) {
    std::cerr << "ERR: Unexpected size." << std::endl;
    return EXIT_FAIL;
  }
  if (exp_info->value_size && exp_info->value_size != info->value_size) {
    std::cerr << "ERR: Unexpected value size." << std::endl;
    return EXIT_FAIL;
  }
  if (exp_info->max_entries && exp_info->max_entries != info->max_entries) {
    std::cerr << "ERR: Unexpected max_entries value." << std::endl;
    return EXIT_FAIL;
  }
  if (exp_info->type && exp_info->type != info->type) {
    std::cerr << "ERR: Unexpected type." << std::endl;
    return EXIT_FAIL;
  }
  return 0;
}

void Map::StatsPoll(struct bpf_map_info* info) {
  std::clog << "Polling stats..." << std::endl;
  struct stats_record prev, record = {0};

  // Initial reading
  StatsCollect(info->type, &record);
  usleep(1000000 / 4);

  while (1) {
    prev = record;
    StatsCollect(info->type, &record);
    StatsPrint(&record, &prev);
    sleep(1);
  }
}

void Map::StatsCollect(__u32 map_type, struct stats_record* stats_rec) {
  __u32 key_pass = XDP_PASS;
  __u32 key_drop = XDP_DROP;

  // TODO: reflect moctok.yaml
  MapCollect(map_type, key_pass, &stats_rec->stats[0]);
  MapCollect(map_type, key_drop, &stats_rec->stats[1]);
}

bool Map::MapCollect(__u32 map_type, __u32 key, struct record* rec) {
  struct datarec value;
  rec->timestamp = gettime();
  switch (map_type) {
    case BPF_MAP_TYPE_ARRAY:
      MapGetValueArray(key, &value);
      break;
    default:
      std::cerr << "Unknown map type." << std::endl;
      return false;
      break;
  }
  rec->total.rx_packets = value.rx_packets;
  rec->total.rx_bytes = value.rx_bytes;
  return true;
}

void Map::MapGetValueArray(__u32 key, struct datarec* value) {
  if ((bpf_wrapper_.BpfMapLookupElem(map_fd_, &key, value)) != 0) {
    std::cerr << "ERR: bpf_map_lookup_elem" << std::endl;
  }
}

void Map::StatsPrint(struct stats_record* stats_rec,
                     struct stats_record* stats_prev) {
  struct record *rec, *prev;
  double period;
  __u64 packets, bytes;
  double pps, bps;

  // TODO: Change this style.
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
