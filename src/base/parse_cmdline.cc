#include "base/parse_cmdline.h"

#include <cassert>
#include <string>

extern "C" {
#include <net/if.h>
#include <unistd.h>
}

#include "base/config.h"
#include "base/logger.h"

namespace {
int check_range_port(uint16_t port) {
  if ((port < 0) | (65535 < port)) {
    LOG_ERROR("Port value is %d. It must be between 0-65535.\n", port);
    return 1;
  }
  return 0;
}
}  // namespace

int parse_cmdline(int argc, char* argv[], struct config& cfg) {
  int opt;
  bool has_i_option = false;
  while ((opt = getopt(argc, argv, "i:d::f::r::a::z::")) != -1) {
    switch (opt) {
      case 'i':
        has_i_option = true;
        cfg.ifname = optarg;
        cfg.ifindex = if_nametoindex(cfg.ifname);
        continue;
      case 'a':
        cfg.run_mode = RunMode::ATTACH;
        continue;
      case 'z':
        cfg.run_mode = RunMode::DETACH;
        continue;
      case 'r':
        cfg.run_mode = RunMode::REWRITE;
        continue;
      case 'd':
        cfg.run_mode = RunMode::DROP;
        continue;
      case 'f':
        cfg.dump_mode = DumpMode::FRIENDLY;
        continue;
      default:
        break;
    }
  }

  if (!has_i_option) {
    LOG_ERROR("Interface must be specified.\n");
    return 1;
  }

  // ensure RunMode
  // DUMPALL, ATTACH, DETACH mode.
  if (optind == argc) {
    assert((cfg.run_mode == RunMode::ATTACH) |
           (cfg.run_mode == RunMode::DETACH) |
           (cfg.run_mode == RunMode::DUMPALL));
    return 0;
  }
  // FILTER mode.
  if ((cfg.run_mode != RunMode::REWRITE) && (cfg.run_mode != RunMode::DROP)) {
    cfg.run_mode = RunMode::FILTER;
  }

  struct filter filt;
  std::string key;
  std::string value;
  int err;

  while (optind < argc) {
    // argc is 2 more than optind at least.
    if (argc - optind < 2) {
      LOG_ERROR("Some option missing. Option must be key-value tuple.\n");
      return 1;
    }

    key = argv[optind++];
    value = argv[optind++];

    // udp_dst
    if (key == "udp_dst") {
      uint16_t port = stoi(value);
      if (check_range_port(port)) {
        return 1;
      }
      filt.udp_dest = port;
      continue;
    }

    // UNREACHABLE
    LOG_ERROR("Unknown option. Abort execution.\n");
    return 1;
  }

  cfg.filter = filt;
  return 0;
}
