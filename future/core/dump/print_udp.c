#include "core/dump/print.h"

#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/udp.h"

void udp_print(const unsigned char* p, uint8_t len) {
  struct udp* udp;

  udp = (struct udp*)p;
  len -= sizeof(*udp);

  printf("UDP %d->%d, ", GET_U16(&udp->src), GET_U16(&udp->dest));
  printf("len %d", len);
}
