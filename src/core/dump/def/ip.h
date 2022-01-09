#ifndef X_IP_H_
#define X_IP_H_

#include "core/dump/def/types.h"

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

struct ip {
	n_uint8_t vhl;
	n_uint8_t tos;
	n_uint16_t tot_len;
	n_uint16_t id;
	n_uint16_t frag_off;
	n_uint8_t ttl;
	n_uint8_t protocol;
	n_uint16_t check;
	n_uint32_t saddr;
	n_uint32_t daddr;
};

#endif // X_IP_H_
