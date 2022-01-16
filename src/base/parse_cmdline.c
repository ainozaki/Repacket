#include "base/parse_cmdline.h"

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/config.h"

void parse_cmdline(int argc, char** argv, struct config* cfg) {
  int opt;
  while ((opt = getopt(argc, argv, "i:d::f::r::a::")) != -1) {
    switch (opt) {
			case 'a':
				cfg->run_mode = ATTACH;
				printf("ATTACH mode\n");
				break;
      case 'i':
        cfg->ifname = optarg;
        cfg->ifindex = if_nametoindex(cfg->ifname);
        break;
      case 'd':
        cfg->run_mode = DETACH;
        break;
      case 'f':
        cfg->run_mode = FILTER;
        break;
      case 'r':
        cfg->run_mode = REWRITE;
        break;
      default:
        printf("unknown cmdline option.\n");
    }
  }

  // parse filtering options.
  const char* dst = "dst";
  const char* host = "host";
  const char* port = "port";
  const char* icmp = "icmp";

  while (optind < argc) {
    if (!strcmp(argv[optind], dst)) {
      optind++;
      if (!strcmp(argv[optind], host)) {
        optind++;
        strcpy(cfg->filter->ip_dst, argv[optind]);
      } else if (!strcmp(argv[optind], port)) {
        optind++;
        strcpy(cfg->filter->tcp_dst, argv[optind]);
        strcpy(cfg->filter->udp_dst, argv[optind]);
      }
    } else if (!strcmp(argv[optind], icmp)) {
      strcpy(cfg->filter->ip_proto, "IPPROTO_ICMP");
    }
    optind++;
  }
}
