#include "core/dump/print.h"

extern "C" {
#include <linux/types.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
}

#include "core/dump/binary_utils.h"
#include "core/dump/print.h"

#define MAC_ADDR_LEN 6U  // Length of MAC address.
#define ETHER_PROTO_LEN 2U

#define X_ETH_P_IPV4 0x0800
#define X_ETH_P_ARP 0x0806
#define X_ETH_P_RARP 0x8035
#define X_ETH_P_VMTP 0x805B
#define X_ETH_P_ATALK 0x809B
#define X_ETH_P_AARP 0x80F3
#define X_ETH_P_IPX 0x8137
#define X_ETH_P_SNMPoE 0x814C
#define X_ETH_P_NET_BIOS 0x8191
#define X_ETH_P_XTP 0x817D
#define X_ETH_P_IPV6 0x86DD
#define X_ETH_P_PPP_DS 0x8863
#define X_ETH_P_PPP_SES 0x8864
#define X_ETH_P_LOOPBACK 0x9000

struct ether_header {
  n_uint48_t dest;
  n_uint48_t src;
  uint16_t type;
};

void StartDump(struct config& config, const unsigned char* p, uint8_t len) {
  switch (config.dump_mode) {
    case DumpMode::NORMAL:
    case DumpMode::FRIENDLY:
      EtherPrint(config, p, len);
      break;
    default:
      // future work
      break;
  }
  printf("\n");
}

void EtherPrint(const struct config& config,
                const unsigned char* p,
                uint8_t len) {
  // time
  struct timeval t;
  struct tm* tm;
  gettimeofday(&t, NULL);
  tm = localtime(&t.tv_sec);
  printf("%02d:%02d:%02d.%06ld ", tm->tm_hour, tm->tm_min, tm->tm_sec,
         t.tv_usec);

  struct ether_header* ethh = (struct ether_header*)p;
  uint16_t type = GET_U16(&ethh->type);
  p += sizeof(struct ether_header);
  len -= sizeof(struct ether_header);

  if (config.dump_mode == DumpMode::FRIENDLY) {
    printf("\n\t|-------8------16------24------32\n");
  }

  switch (type) {
    case X_ETH_P_IPV4:
      IpPrint(config, p, len);
      break;
    case X_ETH_P_ARP:
      ArpPrint(config, p, len);
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
