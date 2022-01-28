#include "core/dump/print.h"

#include <stdio.h>

#include "base/config.h"
#include "core/dump/binary_utils.h"
#include "core/dump/def/arp.h"

void ArpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  struct arp* arp;
  uint16_t opcode;
  char* src_ip;
  char* dst_ip;
  char* src_hw;

  arp = (struct arp*)p;
  opcode = GET_U16(&arp->opcode);
  src_ip = GET_IPADDR(&arp->src_ip);
  dst_ip = GET_IPADDR(&arp->dst_ip);
  src_hw = GET_ETHADDR(&arp->src_hw);

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

void arp_friendly_print(const unsigned char* p, uint8_t len) {
  struct arp* arp = (struct arp*)p;
  uint16_t hwtype = GET_U16(&arp->hw_type);
  uint16_t protype = GET_U16(&arp->proto_type);
  uint8_t hwl = arp->hw_len;
  uint8_t prol = arp->proto_len;
  uint16_t opcode = GET_U16(&arp->opcode);
  char* src_ip = GET_IPADDR(&arp->src_ip);
  char* dst_ip = GET_IPADDR(&arp->dst_ip);
  char* src_hw = GET_ETHADDR(&arp->src_hw);
  char* dst_hw = GET_ETHADDR(&arp->dst_hw);
  switch (opcode) {
    case ARP_REQUEST:
      printf("\t|hwtype%9d|protype%8d|\n", hwtype, protype);
      printf("\t|hwl%4d|prol%3d|opcode%9d|\n", hwl, prol, opcode);
      printf("\t|src_hw%25s|\n", src_hw);
      printf("\t|%15s|src_ip%9s|\n", "", src_ip);
      printf("\t|%15s|dst_hw%9s|\n", "", "");
      printf("\t|dst_hw%25s|\n", dst_hw);
      printf("\t|dst_ip%25s|\n", dst_ip);
      break;
    default:
      break;
  }
}
