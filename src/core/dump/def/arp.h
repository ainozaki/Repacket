#ifndef X_ARP_H
#define X_ARP_H

#include <stdint.h>

#include "core/dump/def/types.h"

#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp_header {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_len;
	uint8_t proto_len;
	uint16_t opcode;
	n_uint48_t src_hw;
	n_uint32_t src_ip;
	n_uint48_t dest_hw;
	n_uint32_t dest_ip;
};

#endif
