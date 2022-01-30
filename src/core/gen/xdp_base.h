#ifndef XDP_PROG_BASE_H_
#define XDP_PROG_BASE_H_

#include <string>

std::string license = "char _license[] SEC(\"license\") = \"GPL\";\n";

// include
std::string include =
    "#include <linux/bpf.h>\n"
    "#include <bpf/bpf_helpers.h>\n"
    "#include <bpf/bpf_endian.h>\n"
    "#include <linux/icmp.h>\n"
    "#include <linux/if_ether.h>\n"
    "#include <linux/ip.h>\n"
    "#include <linux/tcp.h>\n"
    "#include <linux/udp.h>\n"
    "#include <stddef.h>\n"
    "#define MAX_CPUS 128\n"
    "#define SAMPLE_SIZE 1024ul\n"
    "#ifndef IPPROTO_ICMP\n"
    "#define IPPROTO_ICMP 1\n"
    "#endif\n"
    "#ifndef IPPROTO_TCP\n"
    "#define IPPROTO_TCP 6\n"
    "#endif\n"
    "#ifndef IPPROTO_UDP\n"
    "#define IPPROTO_UDP 17\n"
    "#endif\n";

// struct
std::string define_struct =
    "struct bpf_map_def SEC(\"maps\") perf_map = {\n"
    ".type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,\n"
    ".key_size = sizeof(int),\n"
    ".value_size = sizeof(__u32),\n"
    ".max_entries = MAX_CPUS,\n"
    "};\n"
    "struct S {\n"
    "__u16 cookie;\n"
    "__u16 packet_len;\n"
    "} __packed;\n"
    "struct hdr_cursor {\n"
    "void *pos;\n"
    "};\n";

// inline func
std::string always_inline =
    "static __always_inline __u16 csum_fold_helper(__u32 csum){"
    "return ~((csum & 0xffff) + (csum >> 16));"
    "}\n"
    "static __always_inline void calc_csum(void *data_start, int data_size, "
    "__u32 *csum){"
    "*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);"
    "*csum = csum_fold_helper(*csum);"
    "}\n";

std::string sec_base_f =
    "SEC(\"xdp_generated\") "
    "int xdp_parse_prog(struct xdp_md* ctx){\n"
    "void *data = (void *)(long)ctx->data;\n"
    "void *data_end = (void *)(long)ctx->data_end;\n"
    "__u64 flags = BPF_F_CURRENT_CPU;\n"
    "__u16 sample_size;\n"
    "int ret;\n"
    "struct S metadata;\n";
std::string sec_base_b =
    "metadata.cookie = 0xdead;\n"
    "metadata.packet_len = (__u16)(data_end - data);\n"
    "sample_size = metadata.packet_len <= SAMPLE_SIZE ? "
    "metadata.packet_len : SAMPLE_SIZE;\n"
    "flags |= 	(__u64)sample_size << 32;\n"
    "ret = bpf_perf_event_output(ctx, &perf_map, flags, "
    "&metadata, sizeof(metadata));\n"
    "if (ret){\n"
    "bpf_printk(\"perf_event_output failed\");\n"
    "}\n"
    "return XDP_PASS;\n"
    "}\n";

std::string action_base =
    "struct hdr_cursor nh;\n"
    "nh.pos = data;\n"
    "struct ethhdr *eth = nh.pos;\n"
    "nh.pos += sizeof(*eth);\n"
    "if (eth + 1 > data_end){return -1; }\n"
    "if (eth->h_proto != bpf_htons(ETH_P_IP)){\n"
    "return XDP_PASS;\n"
    "}\n"
    "struct iphdr *iph = nh.pos;\n"
    "if (iph + 1 > data_end){ return -1; }\n"
    "nh.pos += sizeof(*iph);\n"
    "struct tcphdr *tcph = NULL;\n"
    "struct udphdr *udph = NULL;\n"
    "struct icmphdr *icmph = NULL;\n"
    "if (iph->protocol == IPPROTO_ICMP){\n"
    "icmph = nh.pos;\n"
    "if (icmph + 1 > data_end) { return XDP_ABORTED;}\n"
    "nh.pos += sizeof(*icmph);}\n"
    "if (iph->protocol == IPPROTO_TCP){\n"
    "tcph = nh.pos;\n"
    "if (tcph + 1 > data_end) { return XDP_ABORTED;}\n"
    "nh.pos += sizeof(*tcph);}\n"
    "if (iph->protocol == IPPROTO_UDP){\n"
    "udph = nh.pos;\n"
    "if (udph + 1 > data_end) { return XDP_ABORTED;}\n"
    "nh.pos += sizeof(*udph);}\n";

std::string filter_base_f = "if (";
std::string filter_base_b = " ){\n return XDP_PASS; }\n";

std::string rewrite_base_f = "if (";
std::string rewrite_base_m = " ){\n";
std::string rewrite_base_b = "}\n";

#endif  // XDP_PROG_BASE_H_
