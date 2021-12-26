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

	/* ip heade */
  std::string ip_protocol;
  std::string ip_saddr;
  std::string ip_daddr;
	int ip_ttl_min = -1;
	int ip_ttl_max = -1;
	// Total Length in IP header is between 46-1500 Byte. 
	int16_t ip_tot_len_min = -1;
	int16_t ip_tot_len_max = -1;
	std::string ip_tos;

	/* icmp header */
	int icmp_type = -1;
	int icmp_code = -1;

	/* tcp header */
	// Source port in tcp haeder is between 0-65535.
  int tcp_src = -1;
  int tcp_dst = -1;
  bool tcp_urg;
  bool tcp_ack;
  bool tcp_psh;
  bool tcp_rst;
  bool tcp_syn;
  bool tcp_fin;

	/* udp header */
  int udp_src = -1;
  int udp_dst = -1;
};

enum class Mode {
	Generate,
	Attach,
	Detach,
	Stats,
};

enum class LogLevel {
	Info,
	Error,
	Debug,
};

struct config {
	Mode mode = Mode::Stats;
  unsigned int xdp_flags;
  unsigned int ifindex;
	std::string ifname;
	std::string yaml_filepath;
	std::string output_filepath;
	std::string bpf_filepath;
  std::string progsec;
};

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40
#define EXIT_FAIL_MAP 50
#define EXIT_SIGNAL 100

#endif /* _DEFINE_H_ */
