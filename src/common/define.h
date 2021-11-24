#ifndef _DEFINE_H_
#define _DEFINE_H_

#include <cstdint>
#include <string>

struct Policy {
  int priority = -1;
  int port = -1;
  std::string ip_address;
  std::string protocol;
};

struct config {
  uint32_t xdp_flags;
  unsigned int ifindex;
  char* ifname;
  char* filename;
  std::string progsec;
};

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40
#define EXIT_FAIL_MAP 50

#endif /* _DEFINE_H_ */
