#include "core/xdp/map_handler.h"

#include <cassert>

extern "C" {
#include <bpf.h>
#include <libbpf.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
}

#include "base/config.h"
#include "base/logger.h"

namespace {

__u64 gettime() {
  struct timespec t;
  int res;
  res = clock_gettime(CLOCK_MONOTONIC, &t);
  if (res < 0) {
    LOG_ERROR("ERR: gettime. ");
    exit(1);
  }
  return (__u64)t.tv_sec * 1000000000 + t.tv_nsec;
}

double calc_period(struct record* rec, struct record* prev) {
  double period_ = 0;
  __u64 period = 0;
  period = rec->timestamp - prev->timestamp;
  if (period > 0) {
    period_ = ((double)period / 1000000000);
  }
  return period_;
}

}  // namespace

MapHandler::MapHandler(const struct config& config, const int map_fd)
    : config_(config), map_fd_(map_fd) {}

void MapHandler::Start() {
  // TODO: make map_info a member of Map
  struct bpf_map_info exp_info, info;
  exp_info.key_size = sizeof(__u32);
  exp_info.value_size = sizeof(struct datarec);
  exp_info.max_entries = 5;
  exp_info.type = BPF_MAP_TYPE_ARRAY;

  int check_result = CheckMapInfo(&exp_info, &info);
  if (check_result) {
    LOG_ERROR("ERR: Failed to get map info.");
    return;
  }

  StatsPoll(&info);
}

int MapHandler::CheckMapInfo(struct bpf_map_info* exp_info,
                             struct bpf_map_info* info) {
  assert(map_fd_ >= 0);

  // BPF-info via bpf-syscall
  __u32 info_len = sizeof(*info);
  if (bpf_obj_get_info_by_fd(map_fd_, info, &info_len)) {
    LOG_ERROR("ERR: Cannot get info.\n");
    return 1;
  }
  if (exp_info->key_size && exp_info->key_size != info->key_size) {
    LOG_ERROR("ERR: Unexpected size.\n");
    return 1;
  }
  if (exp_info->value_size && exp_info->value_size != info->value_size) {
    LOG_ERROR("ERR: Unexpected value size.\n");
    return 1;
  }
  if (exp_info->max_entries && exp_info->max_entries != info->max_entries) {
    LOG_ERROR("ERR: Unexpected max_entries value.\n");
    return 1;
  }
  if (exp_info->type && exp_info->type != info->type) {
    LOG_ERROR("ERR: Unexpected type.\n");
    return 1;
  }
  return 0;
}

void MapHandler::StatsPoll(struct bpf_map_info* info) {
  struct record prev, record = {0};

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

bool MapHandler::StatsCollect(__u32 map_type, struct record* rec) {
  int err;
  struct datarec value;
  rec->timestamp = gettime();

  uint32_t key = 1;
  switch (map_type) {
    case BPF_MAP_TYPE_ARRAY:
      if (bpf_map_lookup_elem(map_fd_, &key, &value)) {
        LOG_ERROR("Err while bpf_map_lookup_elem\n");
        return false;
      }
      break;
    default:
      LOG_ERROR("Unknown map type.");
      return false;
      break;
  }
  rec->total.rx_packets = value.rx_packets;
  rec->total.rx_bytes = value.rx_bytes;
  return true;
}

void MapHandler::StatsPrint(struct record* rec, struct record* prev) {
  double period;
  __u64 packets, bytes;
  double pps, bps;

  std::string action;

  const char* fmt =
      "\rrewrite  %'11lld pkts (%'12.0f pps)"
      " period:%f";

  period = calc_period(rec, prev);
  if (period == 0)
    return;

  packets = rec->total.rx_packets - prev->total.rx_packets;
  pps = packets / period;

  fprintf(stderr, fmt, rec->total.rx_packets, pps, rec->total.rx_bytes, period);
  fflush(stderr);
}
