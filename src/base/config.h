#ifndef DEFINE_H_
#define DEFINE_H_

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>

enum mode { ATTACH, DETACH, DUMPALL, FILTER };

enum proto { ICMP };

struct filter {
  char ip_dst[16];
  char ip_src[16];
  char ip_proto[16];
  char tcp_dst[6];
  char udp_dst[6];
};

struct config {
  __u32 xdp_flags;
  int ifindex;
  char* ifname;
  enum mode run_mode;
  struct filter* filter;
};

#endif  // DEFINE_H_
