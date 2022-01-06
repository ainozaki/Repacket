#include "core/dump/print_ip.h"

#include <stdint.h>
#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/ip.h"

void ip_print(const unsigned char* p, uint8_t len) {
  const struct ip* ip;
  uint8_t proto;

  ip = (const struct ip*)p;
  proto = GET_U8(ip->protocol);
  printf("IP %s", ip_protoname(proto));
}
