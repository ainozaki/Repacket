#include "core/dump/print.h"

#include <string>

extern "C" {
#include <stdint.h>
#include <stdio.h>
#include <string.h>
}

#include "core/dump/binary_utils.h"

#define X_IPPROTO_ICMP 1
#define X_IPPROTO_IGMP 2
#define X_IPPROTO_IP 4
#define X_IPPROTO_TCP 6
#define X_IPPROTO_CBT 7
#define X_IPPROTO_EGP 8
#define X_IPPROTO_IGP 9
#define X_IPPROTO_UDP 17
#define X_IPPROTO_IPv6 41
#define X_IPPROTO_IPv6_Route 43
#define X_IPPROTO_IPv6_Frag 44
#define X_IPPROTO_IDRP 45
#define X_IPPROTO_RSVP 46
#define X_IPPROTO_GRE 47
#define X_IPPROTO_ESP 50
#define X_IPPROTO_AH 51
#define X_IPPROTO_MOBILE 55
#define X_IPPROTO_IPv6_ICMP 58
#define X_IPPROTO_IPv6_NoNxt 59
#define X_IPPROTO_IPv6_Opts 60
#define X_IPPROTO_EIGRP 88
#define X_IPPROTO_OSPF 89
#define X_IPPROTO_IPIP 94
#define X_IPPROTO_PIM 103
#define X_IPPROTO_VRRP 112
#define X_IPPROTO_PGM 113
#define X_IPPROTO_L2TP 115

struct ip_header {
  unsigned int ver : 4;
  unsigned int hl : 4;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};

void IpPrint(const struct config& cfg, const unsigned char* p, uint8_t len) {
  const struct ip_header* iph = (struct ip_header*)p;
  const uint8_t tos = iph->tos;
  const uint16_t tot_len = GET_U16(&iph->tot_len);
  const uint16_t id = GET_U16(&iph->id);

  const uint16_t flag_and_flag_off = iph->frag_off;
  const uint8_t flag = flag_and_flag_off >> 13;
  const uint16_t flag_off = flag_and_flag_off & 0x1fff;
  std::string flags;
  if (flag & 0x02) {
    flags = "DF";
  } else if (flag & 0x01) {
    flags = "MF";
  } else {
    flags = "NA";
  }

  const uint8_t ttl = iph->ttl;
  const uint8_t proto = GET_U8(&iph->protocol);
  const uint16_t csum = GET_U16(&iph->check);
  const char* src = GET_IPADDR(&iph->saddr);
  const char* dest = GET_IPADDR(&iph->daddr);

  uint8_t hdl = iph->hl * 4;
  p += hdl;
  len -= hdl;

  switch (cfg.dump_mode) {
    case DumpMode::FRIENDLY:
      printf("\t|v%2d|hl%1d|tos%4d|totlen%9d|\n", 4, 5, tos, tot_len);
      printf("\t|id%13d|%s|offset%6d|\n", id, flags.c_str(), flag_off);
      printf("\t|ttl%4d|proto%2d|csum%11d|\n", ttl, proto, csum);
      printf("\t|src%28s|\n", src);
      printf("\t|dst%28s|\n", dest);
      break;
    case DumpMode::NORMAL:
      printf("IP %s > %s: ttl %d ", src, dest, ttl);
      break;
    default:
      break;
  }

  switch (proto) {
    case X_IPPROTO_ICMP:
      IcmpPrint(cfg, p, len);
      break;
    case X_IPPROTO_IGMP:
      printf("IGMP");
      break;
    case X_IPPROTO_IP:
      printf("IP");
      break;
    case X_IPPROTO_TCP:
      TcpPrint(cfg, p, len);
      break;
    case X_IPPROTO_CBT:
      printf("CBT");
      break;
    case X_IPPROTO_EGP:
      printf("EGP");
      break;
    case X_IPPROTO_IGP:
      printf("IGP");
      break;
    case X_IPPROTO_UDP:
      UdpPrint(cfg, p, len);
      break;
    case X_IPPROTO_IPv6:
      printf("IPv6");
      break;
    case X_IPPROTO_IPv6_Route:
      printf("IPv6 Route");
      break;
    case X_IPPROTO_IPv6_Frag:
      printf("IPv6 Frag");
      break;
    case X_IPPROTO_IDRP:
      printf("IDRP");
      break;
    case X_IPPROTO_RSVP:
      printf("RSVP");
      break;
    case X_IPPROTO_GRE:
      printf("GRE");
      break;
    case X_IPPROTO_ESP:
      printf("ESP");
      break;
    case X_IPPROTO_AH:
      printf("AH");
      break;
    case X_IPPROTO_MOBILE:
      printf("MOBILE");
      break;
    case X_IPPROTO_IPv6_ICMP:
      printf("IPv6_ICMP");
      break;
    case X_IPPROTO_IPv6_NoNxt:
      printf("IPv6 NoNxt");
      break;
    case X_IPPROTO_IPv6_Opts:
      printf("IPv6 Opts");
      break;
    case X_IPPROTO_EIGRP:
      printf("EIGRP");
      break;
    case X_IPPROTO_OSPF:
      printf("OSPF");
      break;
    case X_IPPROTO_IPIP:
      printf("IPIP");
      break;
    case X_IPPROTO_PIM:
      printf("PIM");
      break;
    case X_IPPROTO_VRRP:
      printf("VRRP");
      break;
    case X_IPPROTO_PGM:
      printf("PGM");
      break;
    case X_IPPROTO_L2TP:
      printf("L2TP");
      break;
  }
}
