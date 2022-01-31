#include "base/parse_cmdline.h"

#include <cassert>
#include <cmath>
#include <string>

extern "C" {
#include <net/if.h>
#include <unistd.h>
}

#include "base/config.h"
#include "base/logger.h"

namespace {
uint32_t ipaddr_from_string(std::string s) {
  uint32_t addr = 0;
  size_t pos;
  std::string delemiter = ".";

  for (int i = 0; i < 4; i++) {
    size_t pos = s.find(delemiter);
    if (pos == std::string::npos) {
      LOG_ERROR("Invalid ip address format.\n");
      exit(1);
    }
    uint16_t sub = std::stoi(s.substr(0, pos));
    if (sub<0 | sub> 255) {
      LOG_ERROR("Invalid ip address value.\n");
      exit(1);
    }
    s.erase(0, pos + delemiter.length());
    addr += pow(2, i * 8) * sub;
  }
  return addr;
}

int check_range_u4(const uint8_t value, const std::string& key) {
  if ((value < 0) | (31 < value)) {
    LOG_ERROR("%s must be between 0-31.\n", key.c_str());
    return 1;
  }
  return 0;
}

int check_range_u8(const uint16_t value, const std::string& key) {
  if ((value < 0) | (255 < value)) {
    LOG_ERROR("%s must be between 0-255.\n", key.c_str());
    return 1;
  }
  return 0;
}

int check_range_u16(const uint32_t value, const std::string& key) {
  if ((value < 0) | (65535 < value)) {
    LOG_ERROR("%s must be between 0-65535.\n", key.c_str());
    return 1;
  }
  return 0;
}

int check_range_u32(const uint64_t value, const std::string& key) {
  if ((value < 0) | (std::pow(2, 32) - 1 < value)) {
    LOG_ERROR("%s must be between 0-4294967295.\n", key.c_str());
    return 1;
  }
  return 0;
}
}  // namespace

int parse_cmdline(int argc, char* argv[], struct config& cfg) {
  int opt;
  bool has_i_option = false;
  while ((opt = getopt(argc, argv, "i:d::f::r::a::z::")) != -1) {
    switch (opt) {
      case 'i':
        has_i_option = true;
        cfg.ifname = optarg;
        cfg.ifindex = if_nametoindex(cfg.ifname);
        continue;
      case 'a':
        cfg.run_mode = RunMode::ATTACH;
        continue;
      case 'z':
        cfg.run_mode = RunMode::DETACH;
        continue;
      case 'r':
        cfg.run_mode = RunMode::REWRITE;
        continue;
      case 'd':
        cfg.run_mode = RunMode::DROP;
        continue;
      case 'f':
        cfg.dump_mode = DumpMode::FRIENDLY;
        continue;
      default:
        break;
    }
  }

  if (!has_i_option) {
    LOG_ERROR("Interface must be specified.\n");
    return 1;
  }

  // ensure RunMode
  // DUMPALL, ATTACH, DETACH mode.
  if (optind == argc) {
    assert((cfg.run_mode == RunMode::ATTACH) |
           (cfg.run_mode == RunMode::DETACH) |
           (cfg.run_mode == RunMode::DUMPALL));
    return 0;
  }
  // FILTER mode.
  if ((cfg.run_mode != RunMode::REWRITE) && (cfg.run_mode != RunMode::DROP)) {
    cfg.run_mode = RunMode::FILTER;
  }

  struct filter filt;
  std::string key;
  std::string value;
  int err;

  while (optind < argc) {
    // argc is 2 more than optind at least.
    if (argc - optind < 2) {
      LOG_ERROR("Some option missing. Option must be key-value tuple.\n");
      return 1;
    }

    key = argv[optind++];
    value = argv[optind++];

    // ip_ver
    if (key == "ip_ver") {
      uint8_t ver = std::stoi(value);
      if (check_range_u4(ver, key)) {
        return 1;
      }
      if (ver != 4) {
        LOG_INFO("Xapture supports only ipv4. Continue.\n");
      }
      filt.ip_ver = ver;
      continue;
    }

    // ip_hl
    if (key == "ip_hl") {
      uint8_t hlen = std::stoi(value);
      if (check_range_u4(hlen, key)) {
        return 1;
      }
      filt.ip_hl = hlen;
      continue;
    }

    // ip_tos
    if (key == "ip_tos") {
      // Type of Service is entered as a hex value.
      uint16_t tos = std::stoi(value, nullptr, 8);
      if (check_range_u8(tos, key)) {
        return 1;
      }
      filt.ip_tos = tos;
      continue;
    }

    // ip_tot_len
    if (key == "ip_tot_len") {
      uint32_t len = std::stoi(value);
      if (check_range_u32(len, key)) {
        return 1;
      }
      if (len<64 | len> 1500) {
        LOG_INFO(
            "The specified total length may don't work correctly. In that "
            "case, please use between 64-1500.\n");
      }
      filt.ip_tot_len = len;
      continue;
    }

    // ip_id
    if (key == "ip_id") {
      uint32_t id = std::stoi(value);
      if (check_range_u32(id, key)) {
        return 1;
      }
      filt.ip_id = id;
      continue;
    }

    // ip_ttl
    if (key == "ip_ttl") {
      uint16_t ttl = std::stoi(value);
      if (check_range_u16(ttl, key)) {
        return 1;
      }
      filt.ip_ttl = ttl;
      continue;
    }

    // ip_protocol
    if (key == "ip_protocol") {
      uint16_t protocol = std::stoi(value);
      if (check_range_u8(protocol, key)) {
        return 1;
      }
      filt.ip_protocol = protocol;
      continue;
    }

    // ip_check
    if (key == "ip_check") {
      uint32_t check = std::stoi(value);
      if (check_range_u16(check, key)) {
        return 1;
      }
      filt.ip_check = check;
      LOG_INFO(
          "Ip checksum is to be rewritten. Xapture doesn't calculate the right "
          "check sum.\n");
      continue;
    }

    // ip_src
    if (key == "ip_src") {
      uint32_t ipaddr = ipaddr_from_string(value + ".");
      filt.ip_src = value;
      continue;
    }

    // tcp_dest
    if (key == "tcp_dest") {
      uint32_t port = std::stoi(value);
      if (check_range_u16(port, key)) {
        return 1;
      }
      filt.tcp_dest = port;
      continue;
    }

    // tcp_src
    if (key == "tcp_src") {
      uint32_t port = std::stoi(value);
      if (check_range_u16(port, key)) {
        return 1;
      }
      filt.tcp_src = port;
      continue;
    }

    // tcp_urg
    if (key == "tcp_urg") {
      if (value == "on" | value == "ON") {
        filt.tcp_urg = true;
      } else if (value == "off" | value == "OFF") {
        filt.tcp_urg = false;
      } else {
        LOG_ERROR("Unknown tcp_urg value.\n");
        return 1;
      }
      continue;
    }

    // tcp_ack
    if (key == "tcp_ack") {
      if (value == "on" | value == "ON") {
        filt.tcp_ack = true;
      } else if (value == "off" | value == "OFF") {
        filt.tcp_ack = false;
      } else {
        LOG_ERROR("Unknown tcp_urg value.\n");
        return 1;
      }
      continue;
    }

    // tcp_psh
    if (key == "tcp_psh") {
      if (value == "on" | value == "ON") {
        filt.tcp_psh = true;
      } else if (value == "off" | value == "OFF") {
        filt.tcp_psh = false;
      } else {
        LOG_ERROR("Unknown tcp_urg value.\n");
        return 1;
      }
      continue;
    }

    // tcp_rst
    if (key == "tcp_rst") {
      if (value == "on" | value == "ON") {
        filt.tcp_rst = true;
      } else if (value == "off" | value == "OFF") {
        filt.tcp_rst = false;
      } else {
        LOG_ERROR("Unknown tcp_urg value.\n");
        return 1;
      }
      continue;
    }

    // tcp_syn
    if (key == "tcp_syn") {
      if (value == "on" | value == "ON") {
        filt.tcp_syn = true;
      } else if (value == "off" | value == "OFF") {
        filt.tcp_syn = false;
      } else {
        LOG_ERROR("Unknown tcp_urg value.\n");
        return 1;
      }
      continue;
    }

    // tcp_fin
    if (key == "tcp_fin") {
      if (value == "on" | value == "ON") {
        filt.tcp_fin = true;
      } else if (value == "off" | value == "OFF") {
        filt.tcp_fin = false;
      } else {
        LOG_ERROR("Unknown tcp_urg value.\n");
        return 1;
      }
      continue;
    }

    // udp_dest
    if (key == "udp_dest") {
      uint32_t port = std::stoi(value);
      if (check_range_u16(port, key)) {
        return 1;
      }
      filt.udp_dest = port;
      continue;
    }

    // udp_src
    if (key == "udp_src") {
      uint32_t port = std::stoi(value);
      if (check_range_u16(port, key)) {
        return 1;
      }
      filt.udp_src = port;
      continue;
    }

    // UNREACHABLE
    LOG_ERROR("Unknown option. Abort execution.\n");
    return 1;
  }

  cfg.filter = filt;
  return 0;
}
