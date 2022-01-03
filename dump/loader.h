#ifndef LOADER_H_
#define LOADER_H_

#include <linux/types.h>

void attach(__u32 xdp_flags, int ifindex, char* ifname);

void detach(int ifindex, char* ifname);

#endif // LOADER_H_
