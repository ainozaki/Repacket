#include "core/dump/print.h"

#include <stdio.h>

#include "core/dump/binary_utils.h"

struct tcp_header {
  uint16_t src;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  unsigned int doff : 4;
  unsigned int res1 : 4;
  unsigned int cwr : 1;
  unsigned int ece : 1;
  unsigned int urg : 1;
  unsigned int ack : 1;
  unsigned int psh : 1;
  unsigned int rst : 1;
  unsigned int syn : 1;
  unsigned int fin : 1;
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};

void TcpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  struct tcp_header* tcph = (struct tcp_header*)p;
  len -= sizeof(*tcph);

  printf("TCP %d->%d, ", GET_U16(&tcph->src), GET_U16(&tcph->dest));
  printf("len %d", len);
}
