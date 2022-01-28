#ifndef X_TCP_H_
#define X_TCP_H_

#include <stdint.h>

struct tcp {
  uint16_t src;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint16_t flags;
  uint16_t window;
  uint16_t check;
  uint16_t urg;
};

#endif  // X_TCP_H_
