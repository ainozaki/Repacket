#include "core/dump/print.h"

#include <stdio.h>

#include "base/config.h"
#include "core/dump/binary_utils.h"
#include "core/dump/def/udp.h"

void UdpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  struct udp_header* udp = (struct udp_header*)p;
  len -= sizeof(*udp);

  printf("UDP %d->%d, ", GET_U16(&udp->src), GET_U16(&udp->dest));
  printf("len %d", len);
}
