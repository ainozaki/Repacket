#ifndef DEFINE_H_
#define DEFINE_H_

#include <cstdint>
#include <optional>

enum class RunMode { ATTACH, DETACH, DUMPALL, DROP, FILTER, REWRITE };

enum class DumpMode { NORMAL, FRIENDLY };

enum proto { ICMP };

struct filter {
  uint32_t ip_src;
  uint32_t ip_dest; // Don't use so far.
  uint8_t ip_ttl;
  uint8_t ip_proto;
  uint8_t ip_tos;
  uint16_t ip_tot_len;

  uint16_t tcp_src;
  uint16_t tcp_dest;
  bool tcp_urg;
  bool tcp_ack;
  bool tcp_psh;
  bool tcp_rst;
  bool tcp_syn;
  bool tcp_fin;

  uint16_t udp_src;
  uint16_t udp_dest;
};

struct config {
  uint32_t xdp_flags;
  int ifindex;
  char *ifname;
  RunMode run_mode;
  DumpMode dump_mode;
  std::optional<struct filter> filter;
  std::optional<struct filter> if_filter;
  std::optional<struct filter> then_filter;
};

#endif // DEFINE_H_
