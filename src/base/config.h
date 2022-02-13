#ifndef DEFINE_H_
#define DEFINE_H_

#include <cstdint>
#include <optional>
#include <string>

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST 1U << 0
#endif

enum class RunMode { ATTACH, DETACH, DUMPALL, REWRITE };

enum class DumpMode { NORMAL, FRIENDLY };

struct filter {
  // ip
  std::optional<uint8_t> ip_ver;
  std::optional<uint8_t> ip_hl;
  std::optional<uint8_t> ip_tos;
  std::optional<uint16_t> ip_tot_len;
  std::optional<uint16_t> ip_id;
  std::optional<bool> ip_flag_0;
  std::optional<bool> ip_flag_df;
  std::optional<bool> ip_flag_mf;
  std::optional<uint16_t> ip_flag_off;
  std::optional<uint8_t> ip_ttl;
  std::optional<uint8_t> ip_protocol;
  std::optional<uint16_t> ip_check;
  // TODO: change to uint16_t
  std::optional<std::string> ip_src;
  std::optional<std::string> ip_dest;  // Don't use so far.
  // tcp
  std::optional<uint16_t> tcp_src;
  std::optional<uint16_t> tcp_dest;
  std::optional<uint32_t> tcp_seq;
  std::optional<uint32_t> tcp_ack_seq;
  std::optional<uint8_t> tcp_doff;
  std::optional<uint8_t> tcp_res1;
  std::optional<uint8_t> tcp_res2;
  std::optional<bool> tcp_urg;
  std::optional<bool> tcp_ack;
  std::optional<bool> tcp_psh;
  std::optional<bool> tcp_rst;
  std::optional<bool> tcp_syn;
  std::optional<bool> tcp_fin;
  std::optional<uint16_t> tcp_window;
  std::optional<uint16_t> tcp_check;
  std::optional<uint16_t> tcp_urg_ptr;
  // udp
  std::optional<uint16_t> udp_src;
  std::optional<uint16_t> udp_dest;
  std::optional<uint16_t> udp_len;
  std::optional<uint16_t> udp_check;
};

struct config {
  uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  int ifindex = -1;
  std::string ifname;
  RunMode run_mode = RunMode::DUMPALL;
  DumpMode dump_mode = DumpMode::NORMAL;
  std::optional<struct filter> filter;
  struct filter if_filter;
  struct filter then_filter;
  bool use_ip;
  bool use_udp;
  bool use_tcp;
  bool use_icmp;
};

#endif  // DEFINE_H_
