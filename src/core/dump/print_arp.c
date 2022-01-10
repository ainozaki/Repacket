#include "core/dump/print.h"

#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/arp.h"

void arp_print(const unsigned char* p, uint8_t len) {
  struct arp* arp;
  uint16_t opcode;
  char* src_ip;
  char* dst_ip;
  char* src_hw;

  arp = (struct arp*)p;
  opcode = GET_U16(arp->opcode);
  src_ip = GET_IPADDR(arp->src_ip);
  dst_ip = GET_IPADDR(arp->dst_ip);
  src_hw = GET_ETHADDR(arp->src_hw);

  printf("ARP, ");
  switch (opcode) {
    case ARP_REQUEST:
      printf("request who-has %s tell %s, ", dst_ip, src_ip);
      break;
    case ARP_REPLY:
      printf("reply %s is-at %s, ", dst_ip, src_hw);
      break;
  }
  printf("len %d", len);
}
