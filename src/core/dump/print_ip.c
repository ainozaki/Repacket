#include "core/dump/print.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/dump/binary_utils.h"
#include "core/dump/def/ip.h"

void ip_print(const unsigned char* p, uint8_t len) {
  const struct ip* ip;
  uint8_t proto;
  char* src;
  char* dst;

  ip = (const struct ip*)p;
  proto = GET_U8(ip->protocol);
  src = GET_IPADDR(ip->saddr);
  dst = GET_IPADDR(ip->daddr);

  uint8_t hdl = (GET_U8(ip->vhl) & 0x0F) * 4;
  p += hdl;
  len -= hdl;

  printf("IP %s > %s: ", src, dst);
  switch (proto) {
    case X_IPPROTO_ICMP:
      icmp_print(p, len);
      break;
    case X_IPPROTO_IGMP:
      printf("IGMP");
      break;
    case X_IPPROTO_IP:
      printf("IP");
      break;
    case X_IPPROTO_TCP:
      tcp_print(p, len);
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
      udp_print(p, len);
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

void ip_friendly_print(const unsigned char* p, uint8_t len) {
  const struct ip* ip;
  char* src;
  char* dst;
  char flag[3] = "";

  ip = (const struct ip*)p;
  uint8_t tos = GET_U8(ip->tos);
  uint16_t tot_len = GET_U16(ip->tot_len);
  uint16_t id = GET_U16(ip->id);
  uint8_t flag_8 = GET_U8(ip->frag_off);
  int one = flag_8 & 0x08;
  int two = flag_8 & 0x04;
  if (one) {
    strcpy(flag, "MF");
  } else if (two) {
    strcpy(flag, "DF");
  } else {
    strcpy(flag, "NA");
  }
  uint16_t flag_off = GET_U16(ip->frag_off) & 0x1fff;
  uint8_t ttl = GET_U8(ip->ttl);
  uint8_t proto = GET_U8(ip->protocol);
  uint16_t csum = GET_U16(ip->check);
  src = GET_IPADDR(ip->saddr);
  dst = GET_IPADDR(ip->daddr);

  uint8_t hdl = (GET_U8(ip->vhl) & 0x0F) * 4;
  p += hdl;
  len -= hdl;
  printf("\t|v%2d|hl%1d|tos%4d|totlen%9d|\n", 4, 5, tos, tot_len);
  printf("\t|id%13d|%s|offset%6d|\n", id, flag, flag_off);
  printf("\t|ttl%4d|proto%2d|csum%11d|\n", ttl, proto, csum);
  printf("\t|src%28s|\n", src);
  printf("\t|dst%28s|\n", dst);
}
