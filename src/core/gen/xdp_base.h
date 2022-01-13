#ifndef XDP_PROG_BASE_H_
#define XDP_PROG_BASE_H_

#include <stdio.h>

const char *license = "char _license[] SEC(\"license\") = \"GPL\";\n";

// include
const char *include = 
		"#include <linux/bpf.h>\n"
		"#include <bpf/bpf_helpers.h>\n"
		"#include <linux/if_ether.h>\n"
		"#include <linux/ip.h>\n"
		"#define MAX_CPUS 128\n"
		"#define SAMPLE_SIZE 1024ul\n"
		"#ifndef IPPROTO_ICMP\n"
		"#define IPPROTO_ICMP 1\n"
		"#endif\n";

// struct
const char *define_struct =
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

const char *sec = "SEC(\"xdp_generated\") "
		"int xdp_parse_prog(struct xdp_md* ctx){\n"
    "void *data = (void *)(long)ctx->data;\n"
		"void *data_end = (void *)(long)ctx->data_end;\n"
		"__u64 flags = BPF_F_CURRENT_CPU;\n"
		"__u16 sample_size;\n"
		"int ret;\n"
		"struct S metadata;\n"
		"struct hdr_cursor nh;\n"
		"nh.pos = data;\n"
		"struct ethhdr *eth = nh.pos;\n"
		"nh.pos += sizeof(*eth);\n"
		"if (eth + 1 > data_end){return -1; }\n"
		"struct iphdr *iph = nh.pos;\n"
		"if (iph + 1 > data_end){ return -1; }\n"
		"if (iph->protocol == %s){ return XDP_PASS; }\n"
		"metadata.cookie = 0xdead;\n"
		"metadata.packet_len = (__u16)(data_end - data);\n"
		"sample_size = metadata.packet_len <= SAMPLE_SIZE ? metadata.packet_len : SAMPLE_SIZE;\n"
		"flags |= 	(__u64)sample_size << 32;\n"
		"ret = bpf_perf_event_output(ctx, &perf_map, flags, &metadata, sizeof(metadata));\n"
		"if (ret){\n"
		"bpf_printk(\"perf_event_output failed\");\n"
		"}\n"
		"return XDP_PASS;\n"
		"}\n";

#endif  // XDP_PROG_BASE_H_
