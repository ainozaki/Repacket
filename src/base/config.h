#ifndef DEFINE_H_
#define DEFINE_H_

#include <cstdint>
#include <optional>
#include <string>

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST 1U << 0
#endif

enum class RunMode { ATTACH, DETACH, DUMPALL, DROP, FILTER, REWRITE };

enum class DumpMode { NORMAL, FRIENDLY };

struct filter {
  // ip
  uint8_t ip_ver = 0;
  uint8_t ip_hl = 0;
  uint8_t ip_tos = 0;
  uint16_t ip_tot_len = 0;
  uint16_t ip_id = 0;
  bool ip_flag_0 = false;
  bool ip_flag_df = false;
  bool ip_flag_mf = false;
  uint16_t ip_flag_off = 0;
  uint8_t ip_ttl = 0;
  uint8_t ip_protocol = 0;
  uint16_t ip_check = 0;
  // TODO: change to uint16_t
  std::string ip_src = "";
  std::string ip_dest = "";  // Don't use so far.
  // tcp
  uint16_t tcp_src = 0;
  uint16_t tcp_dest = 0;
  uint32_t tcp_seq = 0;
  uint32_t tcp_ack_seq = 0;
  uint8_t tcp_doff = 0;
  uint8_t tcp_res1 = 0;
  uint8_t tcp_res2 = 0;
  bool tcp_urg = false;
  bool tcp_ack = false;
  bool tcp_psh = false;
  bool tcp_rst = false;
  bool tcp_syn = false;
  bool tcp_fin = false;
  uint16_t tcp_window = 0;
  uint16_t tcp_check = 0;
  uint16_t tcp_urg_ptr = 0;
  // udp
  uint16_t udp_src = 0;
  uint16_t udp_dest = 0;
  uint16_t udp_len = 0;
  uint16_t udp_check = 0;
};

struct config {
  uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  int ifindex = -1;
  std::string ifname;
  RunMode run_mode = RunMode::DUMPALL;
  DumpMode dump_mode = DumpMode::NORMAL;
  std::optional<struct filter> filter;
  std::optional<struct filter> if_filter;
  std::optional<struct filter> then_filter;
};

#endif  // DEFINE_H_
