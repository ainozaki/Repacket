#ifndef X_ICMP_H_
#define X_ICMP_H_

#include "core/dump/def/types.h"

#define ICMP_ECHO_REPLY 1
#define ICMP_UNREACHABLE 3
#define ICMP_REDIRECT 5
#define ICMP_ECHO_REQUEST 8
#define ICMP_TIME_EXCEEDED 11

struct icmp {
  n_uint8_t type;
  n_uint8_t code;
  n_uint16_t chsum;
};

#endif  // X_ICMP_H_
