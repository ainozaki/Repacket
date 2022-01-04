#ifndef LOADER_H_
#define LOADER_H_

#include <linux/types.h>
#include <stdbool.h>

// Attach "xdp-generated-kern.o" to the interface of |ifindex|.
// Map name is expected to be "perf-map".
int attach(__u32 xdp_flags, int ifindex, char *ifname, int *map_fd);

// Detach xdp program from the interface of |ifindex|.
int detach(__u32 xdp_flags, int ifindex, char *ifname);

#endif // LOADER_H_
