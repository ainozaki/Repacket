#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
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
struct hdr_cursor {
void *pos;
};
struct datarec {
__u64 rx_packets;
__u64 rx_bytes;
};
struct bpf_map_def SEC("maps") array_map = {
.type        = BPF_MAP_TYPE_ARRAY,
.key_size    = sizeof(__u32),
.value_size  = sizeof(struct datarec),
.max_entries = 5,
};
SEC("xdp_generated") int xdp_parse_prog(struct xdp_md* ctx){
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
struct hdr_cursor nh;
nh.pos = data;
struct ethhdr *eth = nh.pos;
nh.pos += sizeof(*eth);
if (eth + 1 > data_end){return -1; }
if (eth->h_proto != bpf_htons(ETH_P_IP)){
return XDP_PASS;
}
struct iphdr *iph = nh.pos;
if (iph + 1 > data_end){ return -1; }
nh.pos += sizeof(*iph);
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
if(iph->check==bpf_htons(51966)){iph->check=bpf_htons(57005);}else {return XDP_PASS;}
struct datarec *rec;
__u32 key = 1;
rec = bpf_map_lookup_elem(&array_map, &key);
if (!rec){return XDP_ABORTED;}
rec->rx_packets++;
return XDP_PASS;}
char _license[] SEC("license") = "GPL";
