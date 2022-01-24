#include "core/dump/print.h"

#include <linux/types.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/ether.h"
#include "core/dump/def/ip.h"
#include "core/dump/print.h"

void start_dump(struct config* config, const unsigned char* p, uint8_t len) {
  switch (config->dump_mode) {
    case NORMAL:
      ether_print(p, len);
      break;
    case FRIENDLY:
      ether_friendly_print(p, len);
      break;
  }
  printf("\n");
}

void ether_print(const unsigned char* p, uint8_t len) {
  struct timeval t;
  struct tm* tm;
  gettimeofday(&t, NULL);
  tm = localtime(&t.tv_sec);
  printf("%02d:%02d:%02d.%06ld ", tm->tm_hour, tm->tm_min, tm->tm_sec,
         t.tv_usec);

  p += MAC_ADDR_LEN * 2;
  len -= MAC_ADDR_LEN * 2;

  uint16_t ethertype = GET_U16(p);
  p += ETHER_PROTO_LEN;
  len -= ETHER_PROTO_LEN;

  switch (ethertype) {
    case X_ETH_P_IPV4:
      ip_print(p, len);
      break;
    case X_ETH_P_ARP:
      arp_print(p, len);
      break;
    case X_ETH_P_RARP:
      printf("RARP");
      break;
    case X_ETH_P_VMTP:
      printf("VMTP");
      break;
    case X_ETH_P_ATALK:
      printf("Apple Talk");
      break;
    case X_ETH_P_AARP:
      printf("AARP");
      break;
    case X_ETH_P_IPX:
      printf("IPX");
      break;
    case X_ETH_P_SNMPoE:
      printf("SNMP over Ethernet");
      break;
    case X_ETH_P_NET_BIOS:
      printf("NetBIOS/NetBEUI");
      break;
    case X_ETH_P_XTP:
      printf("XTP");
      break;
    case X_ETH_P_IPV6:
      printf("IPv6");
      break;
    case X_ETH_P_PPP_DS:
      printf("PPPoE Discovery Stage");
      break;
    case X_ETH_P_PPP_SES:
      printf("PPPoE Session Stage");
      break;
    case X_ETH_P_LOOPBACK:
      printf("Loopback");
      break;
    default:
      printf("unknown ethertype");
      break;
  }
}

void ether_friendly_print(const unsigned char* p, uint8_t len) {
  p += MAC_ADDR_LEN * 2;
  len -= MAC_ADDR_LEN * 2;

  uint16_t ethertype = GET_U16(p);
  p += ETHER_PROTO_LEN;
  len -= ETHER_PROTO_LEN;

  printf("\t|-------8------16------24------32\n");
  switch (ethertype) {
    case X_ETH_P_ARP:
      arp_friendly_print(p, len);
      break;
    case X_ETH_P_IPV4:
      ip_friendly_print(p, len);
      break;
  }
}
