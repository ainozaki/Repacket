#include "core/dump/print.h"

#include <stdio.h>

#include "base/config.h"
#include "core/dump/binary_utils.h"
#include "core/dump/def/arp.h"

void ArpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  struct arp_header* arph = (struct arp_header*)p;
  uint16_t hwtype = GET_U16(&arph->hw_type);
  uint16_t protype = GET_U16(&arph->proto_type);
  uint8_t hwl = arph->hw_len;
  uint8_t prol = arph->proto_len;
  uint16_t opcode = GET_U16(&arph->opcode);
  char* src_hw = GET_ETHADDR(&arph->src_hw);
  char* src_ip = GET_IPADDR(&arph->src_ip);
  char* dest_hw = GET_ETHADDR(&arph->dest_hw);
  char* dest_ip = GET_IPADDR(&arph->dest_ip);

  switch (cfg.dump_mode) {
    case DumpMode::FRIENDLY:
      printf("\t|hwtype%9d|protype%8d|\n", hwtype, protype);
      printf("\t|hwl%4d|prol%3d|opcode%9d|\n", hwl, prol, opcode);
      printf("\t|src_hw%25s|\n", src_hw);
      printf("\t|%15s|src_ip%9s|\n", "", src_ip);
      printf("\t|%15s|dst_hw%9s|\n", "", "");
      printf("\t|dst_hw%25s|\n", dest_hw);
      printf("\t|dst_ip%25s|\n", dest_ip);
      break;
    case DumpMode::NORMAL:
      printf("ARP, ");
      switch (opcode) {
        case ARP_REQUEST:
          printf("request who-has %s tell %s, ", dest_ip, src_ip);
          break;
        case ARP_REPLY:
          printf("reply %s is-at %s, ", dest_ip, src_hw);
          break;
      }
      printf("len %d", len);
      break;
  }
}
