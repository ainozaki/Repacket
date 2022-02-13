#include <cassert>
#include <iostream>
#include <memory>
#include <optional>

#include "base/config.h"
#include "base/logger.h"
#include "base/parse_cmdline.h"
#include "core/gen/generator.h"
#include "core/xdp/loader.h"
#include "core/xdp/perf_handler.h"

int xapture(const struct config& cfg) {
  int map_fd;
  int err;
  std::optional<PerfHandler> perf_handler;
  std::optional<Loader> loader;

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

    case RunMode::ATTACH:
      // Atach XDP program to network interface.
      loader = std::make_optional<Loader>(cfg);
      err = loader->Start();
      if (err) {
        LOG_ERROR("Error while attaching XDP program.\n");
        return 1;
      }

    case RunMode::DETACH:
      // Detach XDP program.
      err = Loader::Detach(cfg);
      if (err) {
        LOG_ERROR("Error while detaching XDP program.\n");
        return 1;
      }
      break;
  }
  return 0;
}

int main(int argc, char* argv[]) {
  struct config cfg;

  if (ParseCmdline(argc, argv, cfg)) {
    LOG_ERROR("Invalid cmdline option is detected. Abort.\n");
    return 1;
  }

  return xapture(cfg);
}
