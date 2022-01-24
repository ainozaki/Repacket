#include "base/parse_cmdline.h"

#include <assert.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/config.h"
#include "base/logger.h"

void check_range_port(const char* p) {
  int port = atoi(p);
  if ((port < 0) | (65535 < port)) {
    LOG_ERROR("Port value is %d. It must be between 0-65535.\n", port);
    exit(1);
  }
}

void parse_cmdline(int argc, char** argv, struct config* cfg) {
  int opt;
  int has_i_option = 0;
  while ((opt = getopt(argc, argv, "i:d::f::r::a::z::")) != -1) {
    switch (opt) {
      case 'i':
        has_i_option = 1;
        cfg->ifname = optarg;
        cfg->ifindex = if_nametoindex(cfg->ifname);
        continue;
      case 'a':
        cfg->run_mode = ATTACH;
        continue;
      case 'z':
        cfg->run_mode = DETACH;
        continue;
      case 'r':
        cfg->run_mode = REWRITE;
        continue;
      case 'd':
        cfg->run_mode = DROP;
        continue;
      case 'f':
        cfg->dump_mode = FRIENDLY;
        continue;
      default:
        break;
    }
  }

  if (!has_i_option) {
    LOG_ERROR("Interface must be specified.\n");
    exit(1);
  }

  // assert run_mode
  // DUMPALL, ATTACH, DETACH mode.
  if (optind == argc) {
    assert((cfg->run_mode == ATTACH) | (cfg->run_mode == DETACH) |
           (cfg->run_mode = DUMPALL));
    if (cfg->run_mode == ATTACH)
      printf("ATTACH\n");
    if (cfg->run_mode == DUMPALL)
      printf("DUMPALL\n");
    return;
  }
  // FILTER mode.
  if ((cfg->run_mode != REWRITE) && (cfg->run_mode != DROP)) {
    cfg->run_mode = FILTER;
  }

  // parse filtering options.
  struct filter* filt = cfg->filter;

  while (optind < argc) {
    // |cfg| has two filter in REWRITE mode.
    if (!strcmp(argv[optind], "if")) {
      optind++;
      filt = cfg->if_filter;
    } else if (!strcmp(argv[optind], "then")) {
      optind++;
      filt = cfg->then_filter;
    }

    // argc is 2 more than optind at least.
    if (argc - optind < 2) {
      LOG_ERROR("Some option missing. Option must be key-value tuple.\n");
      exit(1);
    }

    char* key = argv[optind++];
    char* value = argv[optind++];

    // ip_protocol
    if (!strcmp(key, "ip_protocol")) {
      if (!strcmp(value, "icmp")) {
        strcpy(filt->ip_proto, "IPPROTO_ICMP");
      }
      continue;
    }

    // ip_ttl
    if (!strcmp(key, "ip_ttl")) {
      strcpy(filt->ip_ttl, value);
      LOG_INFO("ip_ttl is %s\n", filt->ip_ttl);
      continue;
    }

    // tcp_src
    if (!strcmp(key, "tcp_src")) {
      check_range_port(value);
      strcpy(filt->tcp_src, value);
      continue;
    }

    // tcp_dst
    if (!strcmp(key, "tcp_dst")) {
      check_range_port(value);
      strcpy(filt->tcp_dst, value);
      continue;
    }

    // udp_src
    if (!strcmp(key, "udp_src")) {
      check_range_port(value);
      strcpy(filt->udp_src, value);
      continue;
    }

    // udp_dst
    if (!strcmp(key, "udp_dst")) {
      check_range_port(value);
      strcpy(filt->udp_dst, value);
      continue;
    }

    // UNREACHABLE
    LOG_ERROR("Unknown option. Abort execution.\n");
    exit(1);
  }
}
