#include "base/parse_cmdline.h"

#include <net/if.h>
#include <stdio.h>
#include <unistd.h>

#include "base/config.h"

void parse_cmdline(int argc, char** argv, struct config* cfg) {
  int opt;
  while ((opt = getopt(argc, argv, "i:d::")) != -1) {
    switch (opt) {
      case 'i':
        cfg->ifname = optarg;
        cfg->ifindex = if_nametoindex(cfg->ifname);
        break;
      case 'd':
        cfg->run_mode = DETACH;
        break;
      default:
        printf("unknown cmdline option.\n");
    }
  }
}
