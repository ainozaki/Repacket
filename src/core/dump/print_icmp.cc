#include "core/dump/print.h"

#include <stdio.h>

#include "base/config.h"
#include "core/dump/binary_utils.h"
#include "core/dump/def/icmp.h"

void IcmpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  struct icmp_header* icmph = (struct icmp_header*)p;
  uint8_t type = icmph->type;
  uint8_t code = icmph->code;
  uint16_t csum = GET_U16(&icmph->chsum);
  uint16_t id = GET_U16(&icmph->id);
  uint16_t seq = GET_U16(&icmph->seq);

  switch (cfg.dump_mode) {
    case DumpMode::FRIENDLY:
      switch (type) {
        case ICMP_ECHO_REQUEST:
          printf("\t|type%3d|code%3d|csum%11d|\n", type, code, csum);
          printf("\t|id%13d|seq%12d|\n", id, seq);
          break;
        default:
          break;
      }
      break;
    case DumpMode::NORMAL:
      printf("ICMP ");
      switch (type) {
        case ICMP_ECHO_REPLY:
          printf("echo reply, ");
          break;
        case ICMP_UNREACHABLE:
          printf("unreachable, ");
          break;
        case ICMP_REDIRECT:
          printf("redirect, ");
          break;
        case ICMP_ECHO_REQUEST:
          printf("echo request, ");
          break;
        case ICMP_TIME_EXCEEDED:
          printf("time exceeded, ");
          break;
        default:
          printf("unknown type, ");
      }
      printf("len %d", len);
      break;
  }
}
