#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#define XDP_ACTION_MAX 5

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

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
  void* pos;
};

static __always_inline int parse_ipv4(void *data, __u64 nh_off, void *data_end, struct iphdr *iph){
	iph = data + nh_off;
	if (iph + 1 > data_end){
		return 0;
	}
	return iph->protocol;
}

static __always_inline int parse_ipv6(void *data, __u64 nh_off, void *data_end, struct ipv6hdr *ip6h){
	ip6h = data + nh_off;
	if (ip6h + 1 > data_end){
		return 0;
	}
	return ip6h->nexthdr;
}

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
int xdp_parse_prog(struct xdp_md* ctx) {
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  struct ethhdr* eth = data;
  __u16 h_proto;
  __u64 nh_off;
  __u32 ipproto;
  int action = XDP_PASS;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) {
    return action;
  }
  h_proto = eth->h_proto;

  // Handle VLAN tagged packet.
  if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
    struct vlan_hdr *vhdr;

    vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end){
      return action;
		}
    h_proto = vhdr->h_vlan_encapsulated_proto;
  }

  // Handle double VLAN tagged packet.
  if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
    struct vlan_hdr *vhdr;

    vhdr = data + nh_off;
    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end){
      return action;
		}
    h_proto = vhdr->h_vlan_encapsulated_proto;
  }

	if (h_proto == bpf_htons(ETH_P_IP)){
		struct iphdr *iph;
		ipproto = parse_ipv4(data, nh_off, data_end, iph);
	}else if (h_proto == bpf_htons(ETH_P_IPV6)){
		struct ipv6hdr *ip6h;
		ipproto = parse_ipv6(data, nh_off, data_end, ip6h);
	}else{
		ipproto = 0;
	}

  __u32 filter_addr_0 = 0x0121a8c0;
  __u32 filter_addr_1 = 0x0121a8c0;

  // priority 0
  if ((iph->protocol == IPPROTO_ICMP) && (iph->saddr == filter_addr_0)) {
    action = XDP_DROP;
    goto out;
  }

  // priority 1
  if (iph->saddr == filter_addr_1) {
    goto out;
  }

out:
  return xdp_stats_func(ctx, action);
}

char _license[] SEC("license") = "GPL";
