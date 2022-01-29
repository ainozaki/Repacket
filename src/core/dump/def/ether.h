#ifndef ETHER_H_
#define ETHER_H_

#include <cstdint>

#include "core/dump/def/types.h"

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

#endif  // ETHER_H_
