#ifndef DEFINE_H_
#define DEFINE_H_

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>

enum mode { ATTACH, DETACH, FILTER };

enum proto { ICMP };

struct filter {
  char ip_dst[sizeof("255.255.255.255")];
  char ip_src[sizeof("255.255.255.255")];
  enum proto ip_proto;
  uint16_t tcp_dst;
  uint16_t udp_dst;
};

struct config {
  __u32 xdp_flags;
  int ifindex;
  char* ifname;
  enum mode run_mode;
  struct filter* filter;
};

#endif  // DEFINE_H_
