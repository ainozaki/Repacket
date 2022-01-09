#include "core/dump/print.h"

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

  uint8_t hdl = (GET_U8(ip->vhl) & 0x0F) * 4;
  p += hdl;
  len -= hdl;

  printf("IP %s > %s: ", src, dst);
  switch (proto) {
    case IPPROTO_ICMP:
      icmp_print(p, len);
      break;
  }
}
