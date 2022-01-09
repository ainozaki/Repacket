#include "core/dump/print.h"

#include <linux/types.h>
#include <stdio.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/ether.h"
#include "core/dump/def/ip.h"

void start_dump(const unsigned char* p, uint8_t len) {
  ether_print(p, len);
  printf("\n");
}

void ether_print(const unsigned char* p, uint8_t len) {
  p += MAC_ADDR_LEN * 2;
  len -= MAC_ADDR_LEN * 2;

  uint16_t ethertype = GET_U16(p);
  p += ETHER_PROTO_LEN;
  len -= ETHER_PROTO_LEN;

  switch (ethertype) {
    case ETHERTYPE_IPv4:
      ip_print(p, len);
      break;
    case ETHERTYPE_ARP:
      printf("ARP");
      break;
    case ETHERTYPE_RARP:
      printf("RARP");
      break;
    case ETHERTYPE_VMTP:
      printf("VMTP");
      break;
    case ETHERTYPE_APPLE_TALK:
      printf("Apple Talk");
      break;
    case ETHERTYPE_AARP:
      printf("AARP");
      break;
    case ETHERTYPE_IPX:
      printf("IPX");
      break;
    case ETHERTYPE_SNMPoE:
      printf("SNMP over Ethernet");
      break;
    case ETHERTYPE_NET_BIOS:
      printf("NetBIOS/NetBEUI");
      break;
    case ETHERTYPE_XTP:
      printf("XTP");
      break;
    case ETHERTYPE_IPv6:
      printf("IPv6");
      break;
    case ETHERTYPE_PPPoE_DS:
      printf("PPPoE Discovery Stage");
      break;
    case ETHERTYPE_PPPoE_SS:
      printf("PPPoE Session Stage");
      break;
    case ETHERTYPE_LOOPBACK:
      printf("Loopback");
      break;
    default:
      printf("unknown ethertype");
      break;
  }
}
