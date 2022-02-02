#include "core/dump/print.h"

#include <stdio.h>

#include "base/config.h"
#include "core/dump/binary_utils.h"

#define ICMP_ECHO_REPLY 1
#define ICMP_UNREACHABLE 3
#define ICMP_REDIRECT 5
#define ICMP_ECHO_REQUEST 8
#define ICMP_TIME_EXCEEDED 11

struct icmp_header {
  uint8_t type;
  uint8_t code;
  uint16_t check;
  union {
    struct idseq {
      uint16_t id;
      uint16_t seq;
    } idseq;
    struct unmtu {
      uint16_t unuse;
      uint16_t next_mtu;
    } unmtu;
    n_uint32_t gwaddr;
  } hun;
#define icmp_id hun.idseq.id
#define icmp_seq hun.idseq.seq
};

void IcmpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  struct icmp_header* icmph = (struct icmp_header*)p;
  uint8_t type = icmph->type;
  uint8_t code = icmph->code;
  uint16_t csum = GET_U16(&icmph->check);
  uint16_t id, seq;

  switch (cfg.dump_mode) {
    case DumpMode::FRIENDLY:
      switch (type) {
        case ICMP_ECHO_REQUEST:
          id = GET_U16(&icmph->icmp_id);
          seq = GET_U16(&icmph->icmp_seq);
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
