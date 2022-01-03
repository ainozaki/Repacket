#ifndef LOADER_H_
#define LOADER_H_

#include <linux/types.h>
#include <stdbool.h>

int attach(__u32 xdp_flags, int ifindex, char *ifname, int *map_fd);

int detach(__u32 xdp_flags, int ifindex, char *ifname);

#endif // LOADER_H_
