#ifndef DEFINE_H_
#define DEFINE_H_

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>

enum run_mode { ATTACH, DETACH, DUMPALL, DROP, FILTER, REWRITE };

enum dump_mode { NORMAL, FRIENDLY };

enum proto { ICMP };

struct filter {
  char ip_dst[16];
  char ip_src[16];
  char ip_proto[16];
  char tcp_src[6];
  char tcp_dst[6];
  char udp_src[6];
  char udp_dst[6];
};

struct config {
  __u32 xdp_flags;
  int ifindex;
  char* ifname;
  enum run_mode run_mode;
  enum dump_mode dump_mode;
  struct filter* filter;
  struct filter* if_filter;
  struct filter* then_filter;
};

#endif  // DEFINE_H_
