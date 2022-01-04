#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 128

struct S {
  __u16 cookie;
  __u16 pkt_len;
} __packed;

struct bpf_map_def SEC("maps") perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

SEC("xdp_generated")
int xdp_dump_prog(struct xdp_md* ctx) {
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;

  __u64 flags = BPF_F_CURRENT_CPU;
  __u16 sample_size;
  int ret;
  struct S metadata;

  metadata.cookie = 0xdead;
  metadata.pkt_len = (__u16)(data_end - data);
  sample_size =
      metadata.pkt_len <= SAMPLE_SIZE ? metadata.pkt_len : SAMPLE_SIZE;

  flags |= (__u64)sample_size << 32;

  ret =
      bpf_perf_event_output(ctx, &perf_map, flags, &metadata, sizeof(metadata));
  if (ret) {
    bpf_printk("perf_event_output failed: %d\n", ret);
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
