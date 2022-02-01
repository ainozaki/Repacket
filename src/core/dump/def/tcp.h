#ifndef X_TCP_H_
#define X_TCP_H_

#include <stdint.h>

struct tcp_header {
  uint16_t src;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  unsigned int doff:4;
	unsigned int res1:4;
	unsigned int cwr:1;
	unsigned int ece:1;
	unsigned int urg:1;
	unsigned int ack:1;
	unsigned int psh:1;
	unsigned int rst:1;
	unsigned int syn:1;
	unsigned int fin:1;
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};

#endif  // X_TCP_H_
