#ifndef DEFINE_H_
#define DEFINE_H_

#include <linux/types.h>
#include <stdbool.h>

enum mode { ATTACH, DETACH, GEN };

struct config {
  __u32 xdp_flags;
  int ifindex;
  char* ifname;
  enum mode run_mode;
};

#endif  // DEFINE_H_
