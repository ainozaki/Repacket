#ifndef X_IP_H_
#define X_IP_H_

#include "core/dump/def/types.h"

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
  uint8_t vhl;
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

#endif  // X_IP_H_
