#ifndef DEFINE_H_
#define DEFINE_H_

#include <stdbool.h>
#include <linux/types.h>

enum mode {
	ATTACH,
	DETACH
};

struct config {
	__u32 xdp_flags;
	int ifindex;
	char* ifname;
	enum mode run_mode;
};

#endif // DEFINE_H_
