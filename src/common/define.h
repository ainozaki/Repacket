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

struct Policy {
  int priority = -1;
	Action action = Action::Pass;
  std::string ip_protocol;
  std::string ip_saddr;
  std::string ip_daddr;
	int ip_ttl_min = -1;
	int ip_ttl_max = -1;
	int16_t ip_tot_len_min = -1;
	int16_t ip_tot_len_max = -1;
  int port = -1;
};

enum class Mode {
	Generate,
	Load,
	Unload,
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
