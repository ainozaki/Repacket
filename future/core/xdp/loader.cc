#include "core/xdp/loader.h"

#include <cassert>
#include <memory>

#include <bpf/bpf.h>
#include <libbpf.h>

#include "base/config.h"
#include "base/logger.h"

int Attach(std::shared_ptr<struct config> cfg, std::shared_ptr<int> map_fd) {
  int err;
  int prog_fd;
  struct bpf_object *bpfobj;
  char bpf_file[] = "xdp-generated-kern.o";
  char bpf_mapname[] = "perf_map";

  assert(cfg->ifname);
  assert(cfg->ifindex > 0);

  // Load BPF program and get fd.
  err = bpf_prog_load(bpf_file, BPF_PROG_TYPE_XDP, &bpfobj, &prog_fd);
  if (!prog_fd) {
    LOG_ERROR("ERR: Cannot load %s (fd: %d)\n", bpf_file, prog_fd);
    return err;
  }

  // Set xdp to the interface.
  err = bpf_set_link_xdp_fd(cfg->ifindex, prog_fd, cfg->xdp_flags);
  if (err) {
    LOG_ERROR("ERR: Cannot set xdp to %s (index %d)\n", cfg->ifname,
              cfg->ifindex);
    return err;
  }

  // Find fd for the map.
  // Perf event handler will use this fd.
  int fd = bpf_object__find_map_fd_by_name(bpfobj, bpf_mapname);
  if (fd < 0) {
    LOG_ERROR("ERR: Cannot find fd for %s (map_fd: %d)\n", bpf_mapname, fd);
    return 1;
  }
  *map_fd = fd;

  LOG_INFO("Success: Attach %s to interface %s\n", bpf_file, cfg->ifname);
  return 0;
}

int Detach(std::shared_ptr<struct config> cfg) {
  // Set xdp to the interface.
  // bpf_set_link_xdp_fd() unloads BPF program when fd is -1.
  if (bpf_set_link_xdp_fd(cfg->ifindex, /*fd=*/-1, cfg->xdp_flags)) {
    LOG_ERROR("ERR: Cannot set xdp to interface on index %d.\n", cfg->ifindex);
    return 1;
  }
  LOG_INFO("Success: Detach XDP program from interface %s\n", cfg->ifname);
  return 0;
}
