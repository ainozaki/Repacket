#include "xapture.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "def/config.h"
#include "loader.h"
#include "logger.h"
#include "perf_event_handler.h"

void xdump(struct config cfg) {
  int err;
  int map_fd = -1;

  switch (cfg.run_mode) {
    case ATTACH:
      // Attach BPF program.
      err = attach(cfg.xdp_flags, cfg.ifindex, cfg.ifname, &map_fd);
      if (err) {
        LOG_ERROR("Err while attaching BPF program.\n");
        return;
      }

      // Perf event.
      err = perf_event(&map_fd);
      if (err) {
        LOG_ERROR("Err while handling perf_event.\n");
        return;
      }
      return;

    case DETACH:
      // Detach BPF program.
      err = detach(cfg.xdp_flags, cfg.ifindex, cfg.ifname);
      if (err) {
        LOG_ERROR("Err while attaching BPF program.\n");
      }
      return;

    default:
      assert(false);
  }
  return;
}
