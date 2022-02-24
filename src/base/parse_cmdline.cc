#include "base/parse_cmdline.h"

#include <cassert>
#include <string>

extern "C" {
#include <net/if.h>
#include <string.h>
}

#include "base/config.h"
#include "base/logger.h"
#include "base/parse_rewrite_option.h"
#include "base/utils.h"

int ParseCmdline(int argc, char* argv[], struct config& cfg) {
  std::string argv_new[argc];
  for (int i = 0; i < argc; i++) {
    argv_new[i] = argv[i];
  }
  return ParseCmdline(argc, argv_new, cfg);
}

int ParseCmdline(int argc, const std::string argv[], struct config& cfg) {
  int index;
  bool has_i_option = false;
  int err;
  bool parse_if = false;
  bool parse_then = false;

  if (argv[0] == "sudo") {
    index = 2;
  } else {
    index = 1;
  }

  while (index < argc) {
    // -a, -d and -i option.
    if (argv[index][0] == '-') {
      const char opt = argv[index][1];
      switch (opt) {
        case 'i':
          has_i_option = true;
          index++;
          cfg.ifname = argv[index];
          cfg.ifindex = if_nametoindex(cfg.ifname.c_str());
          if (!cfg.ifindex) {
            LOG_ERROR("Cannot find interface name %s\n", cfg.ifname.c_str());
            return 1;
          }
          break;
        case 'a':
          if (cfg.run_mode != RunMode::NONE) {
            LOG_ERROR("Cannot specify multiple mode.\n");
            return 1;
          }
          cfg.run_mode = RunMode::ATTACH;
          break;
        case 'd':
          if (cfg.run_mode != RunMode::NONE) {
            LOG_ERROR("Cannot specify multiple mode.\n");
            return 1;
          }
          cfg.run_mode = RunMode::DETACH;
          break;
        default:
          LOG_ERROR("Unknown option %s\n", argv[index].c_str());
          return 1;
          break;
      }
    } else {
      // Rewrite options.
      // Parse "if" and "then"
      if (argv[index] == "if") {
        parse_if = true;
        goto next;
      } else if (argv[index] == "then") {
        parse_if = false;
        parse_then = true;
        goto next;
      }

      // parse "all"
      if (argv[index] == "all") {
        goto next;
      }

      // Parse parameter values.
      std::string key = argv[index++];
      std::string value = argv[index];
      if (parse_if) {
        if (ParseRewriteOption(key, value, cfg.if_filter, cfg)) {
          LOG_ERROR("Invalid rewrite option in [if] expression.\n");
          return 1;
        }
      } else if (parse_then) {
        if (ParseRewriteOption(key, value, cfg.then_filter, cfg)) {
          LOG_ERROR("Invalid rewrite option in [then] expression.\n");
          return 1;
        }
      }
    }
  next:
    index++;
  }  // while

  if (!has_i_option) {
    LOG_ERROR("Interface must be specified.\n");
    return 1;
  }

  // Default mode.
  if (cfg.run_mode == RunMode::NONE) {
    cfg.run_mode = RunMode::REWRITE;
  }
  return 0;
}
