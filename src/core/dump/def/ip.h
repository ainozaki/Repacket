#ifndef IP_H_
#define IP_H_

#include "core/dump/def/types.h"

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

static const char *protocol_name_list[2] = {
	"hoopt",
	"icmp",
};

const char* ip_protoname(const uint8_t protoid)
{
	return protocol_name_list[protoid];
}

#endif // IP_H_
