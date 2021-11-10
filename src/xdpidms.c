#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

//#include "common/common_kern_user.h"

#define XDP_ACTION_MAX 5

#ifndef datarec
#define datrec
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};
#endif

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

SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md* ctx) {
    return xdp_stats_func(ctx, XDP_PASS);
}

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md* ctx) {
    return xdp_stats_func(ctx, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
