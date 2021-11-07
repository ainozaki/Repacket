#include <linux/bpf.h>
#include "../libbpf/src/bpf_helpers.h"

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
