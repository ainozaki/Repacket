#ifndef _DEFINE_H_
#define _DEFINE_H_

#include <string>

struct config {
	__u32 xdp_flags;
	unsigned int ifindex;
	char *ifname;
    char *filename;
    std::string progsec;
};

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#endif /* _DEFINE_H_ */

