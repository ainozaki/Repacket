#include "core/stats/map_handler.h"

#include <bpf.h>
#include <libbpf.h>

#include <cassert>
#include <iostream>

#include "base/bpf_wrapper.h"
#include "base/define/constant.h"
#include "base/define/define.h"
#include "base/utils.h"
#include "base/yaml_handler.h"

MapHandler::MapHandler(int map_fd, const std::string& yaml_filepath)
    : map_fd_(map_fd),
      filter_actions_(YamlHandler::ReadYamlAndGetActions(yaml_filepath)) {
  // Filter size shouldn't exceed the range of int.
  filter_size_ = static_cast<int>(filter_actions_.size());
}

void MapHandler::Start() {
  // TODO: make map_info a member of Map
  struct bpf_map_info exp_info, info;
  exp_info.key_size = sizeof(__u32);
  exp_info.value_size = sizeof(struct datarec);
  exp_info.max_entries = filter_size_;
  exp_info.type = BPF_MAP_TYPE_ARRAY;

  int check_result = CheckMapInfo(&exp_info, &info);
  if (check_result) {
    std::cerr << "ERR: Failed to get map info." << std::endl;
    return;
  }

  StatsPoll(&info);
}

int MapHandler::CheckMapInfo(struct bpf_map_info* exp_info,
                             struct bpf_map_info* info) {
  assert(map_fd_ >= 0);

  int err;
  // BPF-info via bpf-syscall
  err = BpfWrapper::GetMapInfoByFd(map_fd_, info);
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

void MapHandler::StatsPoll(struct bpf_map_info* info) {
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

void MapHandler::StatsCollect(__u32 map_type, struct stats_record* stats_rec) {
  for (int i = 0; i < filter_size_; i++) {
    __u32 filter_priority = i;
    MapCollect(map_type, filter_priority, &stats_rec->stats[i]);
  }
}

bool MapHandler::MapCollect(__u32 map_type, __u32 key, struct record* rec) {
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

void MapHandler::MapGetValueArray(__u32 key, struct datarec* value) {
  if ((BpfWrapper::MapLookupElem(map_fd_, &key, value)) != 0) {
    std::cerr << "ERR: bpf_map_lookup_elem" << std::endl;
  }
}

void MapHandler::StatsPrint(struct stats_record* stats_rec,
                            struct stats_record* stats_prev) {
  struct record *rec, *prev;
  double period;
  __u64 packets, bytes;
  double pps, bps;

  std::string action;
  int filter_priority;

  // TODO: Change this style.
  printf(
      "----------------------------------------------------------------------"
      "-------------------------------------\n");
  for (int i = 0; i < filter_size_; i++) {
    const char* fmt =
        "filter%d     %-6s %'11lld pkts (%'12.0f pps)"
        " %'11lld bytes (%'12.0f bps)"
        " period:%f\n";

    action = ConvertActionToString(filter_actions_[i]);
    filter_priority = i;

    rec = &stats_rec->stats[i];
    prev = &stats_prev->stats[i];

    period = calc_period(rec, prev);
    if (period == 0)
      return;

    packets = rec->total.rx_packets - prev->total.rx_packets;
    pps = packets / period;

    bytes = rec->total.rx_bytes - prev->total.rx_bytes;
    bps = bytes / period;

    printf(fmt, filter_priority, action.c_str(), rec->total.rx_packets, pps,
           rec->total.rx_bytes, bps, period);
  }
}
