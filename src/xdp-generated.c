#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>

#include <linux/ip.h>

#define IPPROTO_ICMP 0x01
#define IPPROTO_TCP 0x06
#define IPPROTO_UDP 0x11
#define XDP_ACTION_MAX 5

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

struct hdr_cursor {
	void *pos;
};

static __always_inline __u32 xdp_stats_func(struct xdp_md* ctx, __u32 action) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;
	struct datarec* rec;

	if (action >= 5) {
		return XDP_ABORTED;
	}

	/* Lookup the map. */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
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
	struct hdr_cursor nh;
	nh.pos = data;

	struct ethhdr *eth = nh.pos;
	if (eth + 1 > data_end){
		return -1;
	}
	nh.pos += sizeof(*eth);
	struct iphdr *iph = nh.pos;
	if ( iph + 1 > data_end){
		return -1;
	}
	int ip_proto = iph->protocol;
	if (ip_proto == IPPROTO_ICMP){
		action = XDP_DROP;
		goto out;
	}
	goto out;
out:
	return xdp_stats_func(ctx, action);
}

char _license[] SEC("license") = "GPL";
