#include <cassert>
#include <iostream>
#include <memory>

#include "base/config.h"
#include "base/logger.h"
#include "base/parse_cmdline.h"
#include "core/gen/generator.h"
#include "core/xdp/loader.h"

extern "C" {
#include <linux/if_link.h>
}

int xapture(const struct config& cfg) {
  int map_fd;

  switch (cfg.run_mode) {
    case RunMode::DUMPALL:
    case RunMode::DROP:
    case RunMode::FILTER:
    case RunMode::REWRITE:
      // Generate XDP program.
      if (Gen(cfg)) {
        LOG_ERROR("Error while generating XDP program.\n");
        return 1;
      }
      // Continue to attach.
      break;

    case RunMode::ATTACH:
      // Atach XDP program to network interface.
      if (Attach(cfg, map_fd)) {
        LOG_ERROR("Error while attaching XDP program.\n");
        return 1;
      }

      // Perf event.
      // if (perf_event(cfg, *map_fd)) {
      //  LOG_ERROR("Error while handling perf_event.\n");
      //  return 1;
      //}
      break;

    case RunMode::DETACH:
      // Detach XDP program.
      if (Detach(cfg)) {
        LOG_ERROR("Error while detaching XDP program.\n");
        return 1;
      }
    default:
      assert(false);
  }
  return 0;
}

int main(int argc, char* argv[]) {
  struct config cfg;
  // TODO: Think twice!
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  cfg.ifindex = -1;
  cfg.run_mode = RunMode::DUMPALL;
  cfg.dump_mode = DumpMode::NORMAL;

  if (parse_cmdline(argc, argv, cfg)) {
    LOG_ERROR("Invalid cmdline option is detected. Abort.\n");
    return 1;
  }

  return xapture(cfg);
}
