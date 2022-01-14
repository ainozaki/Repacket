#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#define MAX_CPUS 128
#define SAMPLE_SIZE 1024ul
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
struct bpf_map_def SEC("maps") perf_map = {
.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
.key_size = sizeof(int),
.value_size = sizeof(__u32),
.max_entries = MAX_CPUS,
};
struct S {
__u16 cookie;
__u16 packet_len;
} __packed;
struct hdr_cursor {
void *pos;
};
SEC("xdp_generated") int xdp_parse_prog(struct xdp_md* ctx){
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
__u64 flags = BPF_F_CURRENT_CPU;
__u16 sample_size;
int ret;
struct S metadata;
struct hdr_cursor nh;
nh.pos = data;
struct ethhdr *eth = nh.pos;
nh.pos += sizeof(*eth);
if (eth + 1 > data_end){return -1; }
struct iphdr *iph = nh.pos;
if (iph + 1 > data_end){ return -1; }
struct tcphdr *tcph = NULL;
struct udphdr *udph = NULL;
struct icmphdr *icmph = NULL;
if (iph->protocol == IPPROTO_ICMP){
icmph = nh.pos;
if (icmph + 1 > data_end) { return XDP_ABORTED;}
nh.pos += sizeof(*icmph);}
if (iph->protocol == IPPROTO_TCP){
tcph = nh.pos;
if (tcph + 1 > data_end) { return XDP_ABORTED;}
nh.pos += sizeof(*tcph);}
if (iph->protocol == IPPROTO_UDP){
udph = nh.pos;
if (udph + 1 > data_end) { return XDP_ABORTED;}
nh.pos += sizeof(*udph);}
if ((iph && iph->protocol!=IPPROTO_ICMP)){ return XDP_PASS; }
metadata.cookie = 0xdead;
metadata.packet_len = (__u16)(data_end - data);
sample_size = metadata.packet_len <= SAMPLE_SIZE ? metadata.packet_len : SAMPLE_SIZE;
flags |= 	(__u64)sample_size << 32;
ret = bpf_perf_event_output(ctx, &perf_map, flags, &metadata, sizeof(metadata));
if (ret){
bpf_printk("perf_event_output failed");
}
return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
