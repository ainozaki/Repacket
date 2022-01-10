#ifndef X_ARP_H
#define X_ARP_H

#include "core/dump/def/types.h"

#define ARP_REQUEST 1
#define ARP_REPLY 2

struct arp {
	n_uint16_t hw_type;
	n_uint16_t proto_type;
	n_uint8_t hw_len;
	n_uint8_t proto_len;
	n_uint16_t opcode;
	n_uint48_t src_hw;
	n_uint32_t src_ip;
	n_uint48_t dst_hw;
	n_uint32_t dst_ip;
};

#endif
