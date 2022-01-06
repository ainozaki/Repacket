#include "core/dump/print_ether.h"

#include <linux/types.h>
#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/ether.h"
#include "core/dump/def/ip.h"
#include "core/dump/print_ip.h"

void start_dump(const unsigned char* p, uint8_t len) {
  ether_print(p, len);
  printf("\n");
}

void ether_print(const unsigned char* p, uint8_t len) {
  p += MAC_ADDR_LEN * 2;
  uint16_t ethertype = GET_U16(p);
  p += ETHER_PROTO_LEN;
  switch (ethertype) {
    case ETHERTYPE_IP:
      ip_print(p, len);
      return;
    default:
      return;
  }
}
