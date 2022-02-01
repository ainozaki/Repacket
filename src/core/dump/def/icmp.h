#ifndef X_ICMP_H_
#define X_ICMP_H_

#include <stdint.h>

#include "core/dump/def/types.h"

#define ICMP_ECHO_REPLY 1
#define ICMP_UNREACHABLE 3
#define ICMP_REDIRECT 5
#define ICMP_ECHO_REQUEST 8
#define ICMP_TIME_EXCEEDED 11

struct icmp_header {
  uint8_t type;
  uint8_t code;
  uint16_t check;
  uint16_t id;
  uint16_t seq;
};

#endif  // X_ICMP_H_
