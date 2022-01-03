#ifndef DEFINE_H_
#define DEFINE_H_

#include <stdbool.h>
#include <linux/types.h>

struct config {
	__u32 xdp_flags;
	int ifindex;
	char* ifname;
	bool is_detach;
};

#endif // DEFINE_H_
