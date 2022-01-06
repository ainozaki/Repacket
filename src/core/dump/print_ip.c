#include "core/dump/print_ip.h"

#include <stdint.h>
#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/ip.h"

void ip_print(const unsigned char* p, uint8_t len) {
  const struct ip* ip;
  uint8_t proto;
  char* src;
  char* dst;

  ip = (const struct ip*)p;
  proto = GET_U8(ip->protocol);
  src = GET_IPADDR(ip->saddr);
  dst = GET_IPADDR(ip->daddr);
  printf("IP %s > %s: %s", src, dst, ip_protoname(proto));
}
