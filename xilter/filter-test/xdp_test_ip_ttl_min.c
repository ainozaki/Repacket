#include <linux/bpf.h>
#include <stddef.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>


#define XDP_ACTION_MAX 5
#define FILTER_SIZE 6

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct datarec),
	.max_entries = FILTER_SIZE,
};

struct hdr_cursor {
	void *pos;
};

static __always_inline __u32 xdp_stats_func(struct xdp_md* ctx, __u32 action, __u32 priority) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;
	struct datarec* rec;

	if (action >= XDP_ACTION_MAX) {
		return XDP_ABORTED;
	}

	if (priority >= FILTER_SIZE) {
		return XDP_ABORTED;
	}

	/* Lookup the map. */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &priority);
	if (!rec) {
		return XDP_ABORTED;
	}

	/* Update the map. */
	__u64 bytes = data_end - data;
	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}

SEC("xdp_generated")
int xdp_parse_prog(struct xdp_md* ctx){
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 action = XDP_PASS;
	__u32 priority = 0;
	struct hdr_cursor nh;
	nh.pos = data;

	struct ethhdr *eth = nh.pos;
	if (eth + 1 > data_end){
		return -1;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)){
		goto out;
	}
	nh.pos += sizeof(*eth);

	struct iphdr *iph = nh.pos;
	if ( iph + 1 > data_end){
		return -1;
	}
	nh.pos += sizeof(*iph);

	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct icmphdr *icmph = NULL;

	if (iph->protocol == IPPROTO_TCP){
		// tcp parse
		tcph = nh.pos;
		if ( tcph + 1 > data_end){
			action = XDP_ABORTED;
			goto out;
		}
		nh.pos += sizeof(*tcph);
	}else if (iph->protocol == IPPROTO_UDP){
		// udp parse
		udph = nh.pos;
		if (udph + 1 > data_end){
			action = XDP_ABORTED;
			goto out;
		}
		nh.pos += sizeof(*udph);
	}else if (iph->protocol == IPPROTO_ICMP){
		// icmp parse
		icmph = nh.pos;
		if ( icmph + 1 > data_end){
			action = XDP_ABORTED;
			goto out;
		}
		nh.pos += sizeof(*icmph);
	}


	// priority 1
	priority++;
	if (iph->ttl >= 255) {
		goto out;
	}

	// priority 2
	priority++;
	if (iph->ttl >= 64) {
		goto out;
	}

	// priority 3
	priority++;
	if (iph->ttl >= 32) {
		goto out;
	}

	// priority 4
	priority++;
	if (iph->ttl >= 16) {
		goto out;
	}

	// priority 5
	priority++;
	if (iph->ttl >= 1) {
		goto out;
	}

	priority++;
out:
	bpf_printk("priority: %d\n", priority);
	return xdp_stats_func(ctx, action, priority);
}

char _license[] SEC("license") = "GPL";
