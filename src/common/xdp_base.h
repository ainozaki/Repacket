#ifndef XDP_PROG_BASE_H_
#define XDP_PROG_BASE_H_

#include <string>

namespace xdp {
const std::string nl = "\n";
const std::string t = "\t";
const std::string l_bracket = "{";
const std::string r_bracket = "}";
const std::string license = "char _license[] SEC(\"license\") = \"GPL\";";

// include
const std::string include =
	"#include <linux/bpf.h>" + nl
	+ "#include <bpf_helpers.h>" + nl
	+ "#include <bpf_endian.h>" + nl
	+ "#include <linux/if_ether.h>" + nl;
const std::string include_ip = "#include <linux/ip.h>" + nl + "#include <linux/in.h>" + nl;
const std::string include_tcp = "#include <linux/tcp.h>" + nl;
const std::string include_udp = "#include <linux/udp.h>" + nl;
const std::string include_icmp = "#include <linux/icmp.h>" + nl;

// define constants
const std::string constant = "#define XDP_ACTION_MAX 5" + nl;

// struct
const std::string struct_map =
    "struct bpf_map_def SEC(\"maps\") xdp_stats_map = {" + nl
		+ t + ".type = BPF_MAP_TYPE_ARRAY," + nl
		+ t + ".key_size = sizeof(__u32)," + nl
		+ t + ".value_size = sizeof(struct datarec)," + nl
		+ t + ".max_entries = XDP_ACTION_MAX," + nl + "};" + nl;

const std::string struct_datarec =
		"struct datarec {" + nl
		+ t + "__u64 rx_packets;" + nl
		+ t + "__u64 rx_bytes;" + nl + "};" + nl;

const std::string struct_hdr_cursor =
    "struct hdr_cursor {" + nl
		+ t + "void *pos;" + nl
		+ "};" + nl;

// inline stats func
const std::string inline_func_stats =
    "static __always_inline __u32 xdp_stats_func(struct xdp_md* ctx, __u32 action) {" + nl
		+ t + "void* data_end = (void*)(long)ctx->data_end;" + nl
		+ t + "void* data = (void*)(long)ctx->data;" + nl
		+ t + "struct datarec* rec;" + nl
		+ nl
		+ t + "if (action >= 5) {" + nl
		+ t + t + "return XDP_ABORTED;" + nl
		+ t + "}" + nl
		+ nl
		+ t + "/* Lookup the map. */" + nl
		+ t + "rec = bpf_map_lookup_elem(&xdp_stats_map, &action);" + nl
		+ t + "if (!rec) {" + nl
		+ t + t + "return XDP_ABORTED;" + nl
		+ t + "}" + nl
		+ nl
		+ t + "/* Update the map. */" + nl
		+ t + "__u64 bytes = data_end - data;" + nl
		+ t + "rec->rx_packets++;" + nl
		+ t + "rec->rx_bytes += bytes;" + nl
		+ nl
		+ t + "return action;" + nl
		+ "}" + nl;

// section
const std::string sec_name = "SEC(\"xdp_generated\")" + nl;

const std::string func_name = "int xdp_parse_prog(struct xdp_md* ctx){" + nl;
const std::string func_fix =
    t + "void *data = (void *)(long)ctx->data;" + nl
		+ t + "void *data_end = (void *)(long)ctx->data_end;" + nl
		+ nl
		+ t + "__u32 action = XDP_PASS;" + nl
		+ t + "struct hdr_cursor nh;" + nl
		+ t + "nh.pos = data;" + nl
		+ nl
		+ t + "struct ethhdr *eth = nh.pos;" + nl
		+ t + "if (eth + 1 > data_end){" + nl
		+ t + t + "return -1;" + nl
		+ t + "}" + nl
		+ t + "nh.pos += sizeof(*eth);" + nl;

const std::string verify_ip = 
		t + "struct iphdr *iph = nh.pos;" + nl
		+ t + "if ( iph + 1 > data_end){" + nl
		+ t + t + "return -1;" + nl
		+ t + "}" + nl;

const std::string func_rule = 
	t + "int ip_proto = iph->protocol;" + nl
	+ t + "if (ip_proto == IPPROTO_ICMP){" + nl
	+ t + t + "action = XDP_DROP;" + nl
	+ t + t + "goto out;" + nl
	+ t + "}" + nl
	+ t +  "goto out;" + nl;

const std::string func_out =
    "out:" + nl
		+ t + "return xdp_stats_func(ctx, action);" + nl;

}  // namespace xdp

#endif  // XDP_PROG_BASE_H_
