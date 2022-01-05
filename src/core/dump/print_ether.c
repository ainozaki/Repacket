#include "core/dump/print_ether.h"

#include <linux/types.h>
#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/ether.h"
#include "core/dump/def/ip.h"

void start_dump(const unsigned char* p, uint8_t len) {
  ether_print(p, len);
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

void ip_print(const unsigned char* p, uint8_t len) {
  const struct ip* ip;
  uint8_t proto;

  ip = (const struct ip*)p;
  proto = GET_U8(ip->protocol);
  printf("IP %s", ip_protoname(proto));
}
