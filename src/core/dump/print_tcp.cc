#include "core/dump/print.h"

#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/tcp.h"

void TcpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  struct tcp_header* tcph = (struct tcp_header*)p;
  len -= sizeof(*tcph);

  printf("TCP %d->%d, ", GET_U16(&tcph->src), GET_U16(&tcph->dest));
  printf("len %d", len);
}
