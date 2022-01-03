#include "xilter.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "define.h"
#include "loader.h"
#include "perf_event_handler.h"

void xilter(struct config cfg) {
  int err;
  int *map_fd;
  switch (cfg.run_mode) {
  case ATTACH:
    // Attach BPF program.
    err = attach(cfg.xdp_flags, cfg.ifindex, cfg.ifname, map_fd);
    if (err) {
      printf("Err while attaching BPF program.\n");
      return;
    }
    printf("Succes: attach\n");

    // Perf event
    err = perf_event(map_fd);
    if (err) {
      printf("Err while handling perf_event.\n");
      return;
    }
    return;

  case DETACH:
    // Detach BPF program.
    err = detach(cfg.xdp_flags, cfg.ifindex, cfg.ifname);
    if (err) {
      printf("Err while attaching BPF program.\n");
    }
    printf("Succes: detach\n");
    return;

  default:
    assert(false);
  }
  return;
}
