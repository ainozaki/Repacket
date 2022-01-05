#include "print_ether.h"

#include <linux/types.h>
#include <stdio.h>

#include "binary_utils.h"
#include "def/ethertype.h"
#include "def/protocol.h"

void start_dump(const unsigned char* p, uint8_t len) {
  ether_print(p, len);
}

void ether_print(const unsigned char* p, uint8_t len) {
  p += MAC_ADDR_LEN * 2;
  uint16_t ethertype = CONVERT_U16(p);
  switch (ethertype) {
    case ETHERTYPE_IP:
      ip_print(p, len);
      return;
    default:
      return;
  }
}

void ip_print(const unsigned char* p, uint8_t len) {
  printf("ip_print\n");
}
