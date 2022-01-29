#include "core/xdp/loader.h"

#include <cassert>
#include <memory>

#include <bpf/bpf.h>
#include <libbpf.h>

#include "base/config.h"
#include "base/logger.h"
#include "core/xdp/perf_handler.h"

Loader::Loader(const struct config& cfg) : config_(cfg) {}

int Loader::Start() {
  // Attach XDP program.
  int err = Attach();
  if (err) {
    LOG_ERROR("Error while attaching XDP program.\n");
    return 1;
  }

  // Setup for collecting stats.
  switch (config_.run_mode) {
    case RunMode::DROP:
      break;
    default:
      // Perf event.
      LOG_DEBUG("map_fd_ : %d\n", map_fd_);
      perf_handler_ = std::make_optional<PerfHandler>(config_, map_fd_);
      err = perf_handler_->Start();
      if (err) {
        LOG_ERROR("Error while perf.\n");
        return 1;
      }
      break;
  }
  return 0;
}

int Loader::Attach() {
  int err;
  int prog_fd;
  struct bpf_object* bpfobj;
  char bpf_file[] = "xdp-generated-kern.o";
  char bpf_mapname[] = "perf_map";

  assert(config_.ifname);
  assert(config_.ifindex > 0);

  // Load BPF program and get fd.
  err = bpf_prog_load(bpf_file, BPF_PROG_TYPE_XDP, &bpfobj, &prog_fd);
  if (!prog_fd) {
    LOG_ERROR("ERR: Cannot load %s (fd: %d)\n", bpf_file, prog_fd);
    return err;
  }

  // Set xdp to the interface.
  err = bpf_set_link_xdp_fd(config_.ifindex, prog_fd, config_.xdp_flags);
  if (err) {
    LOG_ERROR("ERR: Cannot set xdp to %s (index %d)\n", config_.ifname,
              config_.ifindex);
    return err;
  }

  // Find fd for the map.
  map_fd_ = bpf_object__find_map_fd_by_name(bpfobj, bpf_mapname);
  if (map_fd_ < 0) {
    LOG_ERROR("ERR: Cannot find fd for %s (map_fd: %d)\n", bpf_mapname,
              map_fd_);
    return 1;
  }
  LOG_DEBUG("map_fd_ : %d\n", map_fd_);

  LOG_INFO("Success: Attach %s to interface %s\n", bpf_file, config_.ifname);
  return 0;
}

int Loader::Detach() {
  // Set xdp to the interface.
  // bpf_set_link_xdp_fd() unloads BPF program when fd is -1.
  if (bpf_set_link_xdp_fd(config_.ifindex, /*fd=*/-1, config_.xdp_flags)) {
    LOG_ERROR("ERR: Cannot set xdp to interface on index %d.\n",
              config_.ifindex);
    return 1;
  }
  LOG_INFO("Success: Detach XDP program from interface %s\n", config_.ifname);
  return 0;
}
