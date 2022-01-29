#include "core/dump/print.h"

extern "C" {
#include <linux/types.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
}

#include "core/dump/binary_utils.h"
#include "core/dump/def/ether.h"
#include "core/dump/def/ip.h"
#include "core/dump/print.h"

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
