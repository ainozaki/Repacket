#ifndef X_UDP_H_
#define X_UDP_H_

#include <stdint.h>

struct udp {
  uint16_t src;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};

#endif  // X_UDP_H_
