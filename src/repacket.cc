#include <cassert>
#include <iostream>
#include <memory>
#include <optional>

#include "base/config.h"
#include "base/logger.h"
#include "base/parse_cmdline.h"
#include "core/gen/gen_controller.h"
#include "core/xdp/loader.h"

int repacket(const struct config& cfg) {
  std::optional<Loader> loader;

  switch (cfg.run_mode) {
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
      if (loader->Start()) {
        LOG_ERROR("Error while attaching XDP program.\n");
        return 1;
      }

    case RunMode::DETACH:
      // Detach XDP program.
      if (Loader::Detach(cfg)) {
        LOG_ERROR("Error while detaching XDP program.\n");
        return 1;
      }
      break;
    default:
      LOG_ERROR("Unspecified RunMode");
      return 1;
  }
  return 0;
}

int main(int argc, char* argv[]) {
  struct config cfg;

  if (ParseCmdline(argc, argv, cfg)) {
    LOG_ERROR("Invalid cmdline option is detected. Abort.\n");
    return 1;
  }

  return repacket(cfg);
}
