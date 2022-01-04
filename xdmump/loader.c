#include "loader.h"

#include <bpf/bpf.h>
#include <libbpf.h>
#include <linux/types.h>
#include <stdbool.h>

int attach(__u32 xdp_flags, int ifindex, char *ifname, int *map_fd) {
  int err;
  int prog_fd;
  struct bpf_object *bpfobj;
  char *bpf_file = "xdp-generated-dump.o";
  char *bpf_mapname = "perf_map";

  // Load BPF program and get fd.
  err = bpf_prog_load(bpf_file, BPF_PROG_TYPE_XDP, &bpfobj, &prog_fd);
  if (!prog_fd) {
    printf("ERR: Cannot load %s (fd: %d)\n", bpf_file, prog_fd);
    return err;
  }

  // Set xdp to the interface.
  err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
  if (err) {
    printf("ERR: Cannot set xdp to interface on index %d.\n", ifindex);
    return err;
  }

  // Find fd for the map.
  int fd = bpf_object__find_map_fd_by_name(bpfobj, bpf_mapname);
  if (fd < 0) {
    printf("ERR: Cannot find fd for %s (map_fd: %d)\n", bpf_mapname, fd);
    return -1;
  }
  *map_fd = fd;

  return 0;
}

int detach(__u32 xdp_flags, int ifindex, char *ifname) {
  // Set xdp to the interface.
  // bpf_set_link_xdp_fd() unloads BPF program when fd is -1.
  int err = bpf_set_link_xdp_fd(ifindex, /*fd=*/-1, xdp_flags);
  if (err) {
    printf("ERR: Cannot set xdp to interface on index %d.\n", ifindex);
    return err;
  }
  return 0;
}
