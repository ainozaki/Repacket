#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>


#define XDP_ACTION_MAX 5

#define IP_PROTO_ICMP 0x01

#define ETH_ALEN 6

#ifndef datarec
#define datrec
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};
#endif

struct hdr_cursor {
	void *pos;
};

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

struct bpf_map_def SEC("maps") xdp_stats_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct datarec),
    .max_entries = XDP_ACTION_MAX,
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
	struct ethhdr eth;

	nh.pos = data + sizeof(eth);
	struct iphdr *iph = nh.pos;
	if ( iph + 1 > data_end)
		return -1;
	int ip_proto = iph->protocol;
	if (ip_proto != IP_PROTO_ICMP){
		goto out;
	}
	action = XDP_DROP;
out:
	return xdp_stats_func(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md* ctx) {
    return xdp_stats_func(ctx, XDP_PASS);
}

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md* ctx) {
    return xdp_stats_func(ctx, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
