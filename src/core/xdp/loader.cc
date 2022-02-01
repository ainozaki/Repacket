#include "core/xdp/loader.h"

#include <cassert>
#include <memory>

extern "C" {
#include <bpf/bpf.h>
#include <libbpf.h>
#include <unistd.h>
}

#include "base/config.h"
#include "base/logger.h"
#include "core/xdp/map_handler.h"
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
      // Map
      err = PinMaps();
      if (err) {
        LOG_ERROR("Error while perf.\n");
        return 1;
      }
      map_handler_ = std::make_optional<MapHandler>(config_);
      map_handler_->Start();
      break;
    default:
      // Perf event.
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
  char bpf_file[] = "xdp-generated-kern.o";
  char bpf_mapname[] = "perf_map";

  assert(config_.ifname != "");
  assert(config_.ifindex > 0);

  // Load BPF program and get fd.
  err = bpf_prog_load(bpf_file, BPF_PROG_TYPE_XDP, &bpf_obj_, &prog_fd);
  if (!prog_fd) {
    LOG_ERROR("ERR: Cannot load %s (fd: %d)\n", bpf_file, prog_fd);
    return err;
  }

  // Set xdp to the interface.
  err = bpf_set_link_xdp_fd(config_.ifindex, prog_fd, config_.xdp_flags);
  if (err) {
    LOG_ERROR("ERR: Cannot set xdp to %s (index %d)\n", config_.ifname.c_str(),
              config_.ifindex);
    return err;
  }

  // Find fd for the map.
  map_fd_ = bpf_object__find_map_fd_by_name(bpf_obj_, bpf_mapname);
  if (map_fd_ < 0) {
    LOG_ERROR("ERR: Cannot find fd for %s (map_fd: %d)\n", bpf_mapname,
              map_fd_);
    return 1;
  }

  LOG_INFO("Success: Attach %s to interface %s\n", bpf_file,
           config_.ifname.c_str());
  return 0;
}

int Loader::PinMaps() {
  char pin_dir[32];
  sprintf(pin_dir, "/sys/fs/bpf/%s", config_.ifname.c_str());
  int err;
  // Unpin maps in advance.
  if (access(pin_dir, F_OK) != -1) {
    err = bpf_object__unpin_maps(bpf_obj_, pin_dir);
    if (err) {
      LOG_ERROR("Failed: Cannot unpinning maps to %s.", pin_dir);
      return 1;
    }
    LOG_INFO("Success: Unpinned maps!!!");
  }

  // Pin maps.
  err = bpf_object__pin_maps(bpf_obj_, pin_dir);
  if (err) {
    LOG_ERROR("Failed: Cannot pinning maps at %s.", pin_dir);
    return 1;
  }
  LOG_INFO("Success: Pinning maps at %s.", pin_dir);
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
  LOG_INFO("Success: Detach XDP program from interface %s\n",
           config_.ifname.c_str());
  return 0;
}
