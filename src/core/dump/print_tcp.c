#include "core/dump/print.h"

#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/tcp.h"

void tcp_print(const unsigned char* p, uint8_t len) {
  struct tcp* tcph;

  tcph = (struct tcp*)p;
  len -= sizeof(*tcph);

  printf("TCP %d->%d, ", GET_U16(&tcph->src), GET_U16(&tcph->dest));
  printf("len %d", len);
}
