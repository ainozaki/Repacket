#ifndef DEFINE_H_
#define DEFINE_H_

#include <cstdint>
#include <optional>

enum class RunMode { ATTACH, DETACH, DUMPALL, DROP, FILTER, REWRITE };

enum class DumpMode { NORMAL, FRIENDLY };

enum proto { ICMP };

struct filter {
  uint32_t ip_src = 0;
  uint32_t ip_dest = 0;  // Don't use so far.
  uint8_t ip_ttl = 0;
  uint8_t ip_proto = 0;
  uint8_t ip_tos = 0;
  uint16_t ip_tot_len = 0;
  uint16_t tcp_src = 0;
  uint16_t tcp_dest = 0;
  bool tcp_urg = false;
  bool tcp_ack = false;
  bool tcp_psh = false;
  bool tcp_rst = false;
  bool tcp_syn = false;
  bool tcp_fin = false;
  uint16_t udp_src = 0;
  uint16_t udp_dest = 0;
};

struct config {
  uint32_t xdp_flags;
  int ifindex;
  char* ifname;
  RunMode run_mode;
  DumpMode dump_mode;
  std::optional<struct filter> filter;
  std::optional<struct filter> if_filter;
  std::optional<struct filter> then_filter;
};

#endif  // DEFINE_H_
