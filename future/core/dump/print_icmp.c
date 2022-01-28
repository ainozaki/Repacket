#include "core/dump/print.h"

#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/icmp.h"

void icmp_print(const unsigned char* p, uint8_t len) {
  struct icmp* icmp = (struct icmp*)p;
  uint8_t icmp_type = icmp->type;

  printf("ICMP ");
  switch (icmp_type) {
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
}

void icmp_friendly_print(const unsigned char* p, uint8_t len) {
  struct icmp* icmp = (struct icmp*)p;
  uint8_t type = icmp->type;
  uint8_t code = icmp->code;
  uint16_t csum = GET_U16(&icmp->chsum);
  uint16_t id = GET_U16(&icmp->id);
  uint16_t seq = GET_U16(&icmp->seq);
  switch (type) {
    case ICMP_ECHO_REQUEST:
      printf("\t|type%3d|code%3d|csum%11d|\n", type, code, csum);
      printf("\t|id%13d|seq%12d|\n", id, seq);
      break;
    default:
      break;
  }
}
