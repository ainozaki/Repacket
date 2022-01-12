#include <assert.h>
#include <linux/if_link.h>
#include <stdbool.h>
#include <stdio.h>

#include "base/config.h"
#include "base/logger.h"
#include "base/parse_cmdline.h"
#include "core/gen/generator.h"
#include "core/xdp/loader.h"
#include "core/xdp/perf_event_handler.h"

void xdump(struct config cfg) {
  int err;
  int map_fd = -1;

  switch (cfg.run_mode) {
		case GEN:
			err = gen(&cfg);
			if (err) {
				LOG_ERROR("Err while generating XDP program.\n");
				return;
			}
			return;
			// Continue to attach.

    case ATTACH:
      // Attach BPF program.
      err = attach(&cfg, &map_fd);
      if (err) {
        LOG_ERROR("Err while attaching BPF program.\n");
        return;
      }

      // Perf event.
      err = perf_event(&cfg, &map_fd);
      if (err) {
        LOG_ERROR("Err while handling perf_event.\n");
        return;
      }
      return;

    case DETACH:
      // Detach BPF program.
      err = detach(&cfg);
      if (err) {
        LOG_ERROR("Err while attaching BPF program.\n");
      }
      return;

    default:
      assert(false);
  }
  return;
}

int main(int argc, char** argv) {
  struct config cfg = {
      .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
      .ifindex = -1,
      .run_mode = ATTACH,
  };
  parse_cmdline(argc, argv, &cfg);

  xdump(cfg);

  return 0;
}
