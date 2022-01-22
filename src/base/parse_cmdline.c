#include "base/parse_cmdline.h"

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/config.h"
#include "base/logger.h"

void check_range_port(const char* p) {
  int port = atoi(p);
  if (port < 0 | 65535 < port) {
    LOG_ERROR("Port value is %d. It must be between 0-65535.\n", port);
    exit(1);
  }
}

void parse_cmdline(int argc, char** argv, struct config* cfg) {
  int opt;
  while ((opt = getopt(argc, argv, "i:d::f::r::a::z::")) != -1) {
    switch (opt) {
      case 'a':
        cfg->run_mode = ATTACH;
        break;
      case 'd':
        cfg->run_mode = DROP;
        break;
      case 'i':
        cfg->ifname = optarg;
        cfg->ifindex = if_nametoindex(cfg->ifname);
        break;
      case 'z':
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
  const char* ip_protocol = "ip_protocol";
  const char* tcp_src = "tcp_src";
  const char* tcp_dst = "tcp_dst";
  const char* udp_src = "udp_src";
  const char* udp_dst = "udp_dst";

  while (optind < argc) {
    char* key = argv[optind++];
    char* value = argv[optind++];

    // ip_protocol
    if (!strcmp(key, ip_protocol)) {
      if (!strcmp(value, "icmp")) {
        strcpy(cfg->filter->ip_proto, "IPPROTO_ICMP");
      }
    }

    // tcp_src
    if (!strcmp(key, tcp_src)) {
      check_range_port(value);
      strcpy(cfg->filter->tcp_src, value);
    }

    // tcp_dst
    if (!strcmp(key, tcp_dst)) {
      check_range_port(value);
      strcpy(cfg->filter->tcp_dst, value);
    }

    // udp_src
    if (!strcmp(key, udp_src)) {
      check_range_port(value);
      strcpy(cfg->filter->udp_src, value);
    }

    // udp_dst
    if (!strcmp(key, udp_dst)) {
      check_range_port(value);
      strcpy(cfg->filter->udp_dst, value);
    }
  }
}
