#ifndef _DEFINE_H_
#define _DEFINE_H_

#include <cstdint>
#include <string>

constexpr int kSuccess = 0;
constexpr int kError = 1;

struct datarec {
  uint64_t rx_packets;
  uint64_t rx_bytes;
};

enum class Action {
	Pass = 0,
	Drop = 1,
};

struct Filter {
  int priority = -1;
	Action action = Action::Pass;
	// ip header property
  std::string ip_protocol;
  std::string ip_saddr;
  std::string ip_daddr;
	int ip_ttl_min = -1;
	int ip_ttl_max = -1;
	int16_t ip_tot_len_min = -1;
	int16_t ip_tot_len_max = -1;
	std::string ip_tos;
	// icmp header property
	int icmp_type = -1;
	int icmp_code = -1;
	// tcp header property
  int16_t tcp_src = -1;
  int16_t tcp_dst = -1;
  bool tcp_urg;
  bool tcp_ack;
  bool tcp_psh;
  bool tcp_rst;
  bool tcp_syn;
  bool tcp_fin;
};

enum class Mode {
	Generate,
	Attach,
	Detach,
	Stats,
};

struct config {
	Mode mode = Mode::Stats;
  uint32_t xdp_flags;
  unsigned int ifindex;
	std::string ifname;
	std::string bpf_filepath;
  std::string progsec;
	std::string yaml_filepath;
};

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40
#define EXIT_FAIL_MAP 50
#define EXIT_SIGNAL 100

#endif /* _DEFINE_H_ */
