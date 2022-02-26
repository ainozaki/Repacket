#include "base/parse_rewrite_option.h"

#include <cassert>
#include <string>

extern "C" {
#include <net/if.h>
#include <string.h>
}

#include "base/config.h"
#include "base/logger.h"
#include "base/utils.h"

int ParseRewriteOption(const std::string& key,
                       const std::string& value,
                       struct filter& filt,
                       struct config& cfg) {
  // ip_ver
  if (key == "ip_ver") {
    int ver = std::stoi(value, nullptr, 0);
    if (check_range_u4(ver, key)) {
      return 1;
    }
    if (ver != 4) {
      LOG_INFO("Xapture supports only ipv4. Continue.\n");
    }
    filt.ip_ver = ver;
    cfg.use_ip = true;
    return 0;
  }

  // ip_hl
  if (key == "ip_hl") {
    int hlen = std::stoi(value, nullptr, 0);
    if (check_range_u4(hlen, key)) {
      return 1;
    }
    filt.ip_hl = hlen;
    cfg.use_ip = true;
    return 0;
  }

  // ip_tos
  if (key == "ip_tos") {
    int tos = std::stoi(value, nullptr, 0);
    if (check_range_u8(tos, key)) {
      return 1;
    }
    filt.ip_tos = tos;
    cfg.use_ip = true;
    return 0;
  }

  // ip_dscp
  if (key == "ip_dscp") {
    int dscp = std::stoi(value, nullptr, 0);
    if (check_range_u6(dscp, key)) {
      return 1;
    }
    filt.ip_dscp = dscp;
    cfg.use_ip = true;
    return 0;
  }

  // ip_ecn
  if (key == "ip_ecn") {
    int ecn = std::stoi(value, nullptr, 0);
    if (check_range_u2(ecn, key)) {
      return 1;
    }
    filt.ip_ecn = ecn;
    cfg.use_ip = true;
    return 0;
  }

  // ip_tot_len
  if (key == "ip_tot_len") {
    int len = std::stoi(value, nullptr, 0);
    if (check_range_u16(len, key)) {
      return 1;
    }
    filt.ip_tot_len = len;
    cfg.use_ip = true;
    return 0;
  }

  // ip_id
  if (key == "ip_id") {
    int id = std::stoi(value, nullptr, 0);
    if (check_range_u16(id, key)) {
      return 1;
    }
    filt.ip_id = id;
    cfg.use_ip = true;
    return 0;
  }

  // ip_flags
  if (key == "ip_flags") {
    int flags = std::stoi(value, nullptr, 0);
    if (check_range_u4(flags, key)) {
      return 1;
    }
    filt.ip_flags = flags;
    cfg.use_ip = true;
    return 0;
  }

  // ip_flag_res
  if (key == "ip_flag_res") {
    if (value == "on") {
      filt.ip_flag_res = true;
    } else if (value == "off") {
      filt.ip_flag_res = false;
    } else {
      LOG_ERROR("ip_flag_res expects only on/off.\n");
      return 1;
    }
    cfg.use_ip = true;
    return 0;
  }

  // ip_flag_df
  if (key == "ip_flag_df") {
    if (value == "on") {
      filt.ip_flag_df = true;
    } else if (value == "off") {
      filt.ip_flag_df = false;
    } else {
      LOG_ERROR("ip_flag_df expects only on/off.\n");
      return 1;
    }
    cfg.use_ip = true;
    return 0;
  }

  // ip_flag_mf
  if (key == "ip_flag_mf") {
    if (value == "on") {
      filt.ip_flag_mf = true;
    } else if (value == "off") {
      filt.ip_flag_mf = false;
    } else {
      LOG_ERROR("ip_flag_mf expects only on/off.\n");
      return 1;
    }
    cfg.use_ip = true;
    return 0;
  }

  // ip_offset
  if (key == "ip_offset") {
    int offset = std::stoi(value, nullptr, 0);
    if (check_range_u2(offset, key)) {
      return 1;
    }
    filt.ip_offset = offset;
    cfg.use_ip = true;
    return 0;
  }

  // ip_ttl
  if (key == "ip_ttl") {
    int ttl = std::stoi(value, nullptr, 0);
    if (check_range_u8(ttl, key)) {
      return 1;
    }
    filt.ip_ttl = ttl;
    cfg.use_ip = true;
    return 0;
  }

  // ip_protocol
  if (key == "ip_protocol") {
    int protocol = std::stoi(value, nullptr, 0);
    if (check_range_u8(protocol, key)) {
      return 1;
    }
    filt.ip_protocol = protocol;
    cfg.use_ip = true;
    return 0;
  }

  // ip_check
  if (key == "ip_check") {
    int check = std::stoi(value, nullptr, 0);
    if (check_range_u16(check, key)) {
      return 1;
    }
    filt.ip_check = check;
    LOG_INFO(
        "Ip checksum is to be rewritten. Xapture doesn't calculate the "
        "right "
        "check sum.\n");
    cfg.use_ip = true;
    return 0;
  }

  // ip_src
  if (key == "ip_src") {
    if (check_range_ipaddr(value)) {
      LOG_ERROR("Invalid IP address.\n");
      return 1;
    }
    filt.ip_src = value;
    cfg.use_ip = true;
    return 0;
  }

  // tcp_src
  if (key == "tcp_src") {
    int port = std::stoi(value, nullptr, 0);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt.tcp_src = port;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_dest
  if (key == "tcp_dest") {
    int port = std::stoi(value, nullptr, 0);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt.tcp_dest = port;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_seq
  if (key == "tcp_seq") {
    int64_t seq = std::stoll(value, nullptr, 0);
    if (check_range_u32(seq, key)) {
      return 1;
    }
    filt.tcp_seq = seq;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_ack_seq
  if (key == "tcp_ack_seq") {
    int64_t ack_seq = std::stoll(value, nullptr, 0);
    if (check_range_u32(ack_seq, key)) {
      return 1;
    }
    filt.tcp_ack_seq = ack_seq;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_hlen
  if (key == "tcp_hlen") {
    uint8_t hlen = std::stoi(value, nullptr, 0);
    if (check_range_u4(hlen, key)) {
      return 1;
    }
    filt.tcp_hlen = hlen;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_res
  if (key == "tcp_res") {
    uint8_t res = std::stoi(value, nullptr, 0);
    if (check_range_u3(res, key)) {
      return 1;
    }
    filt.tcp_res = res;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_nonce
  if (key == "tcp_nonce") {
    if (value == "on" | value == "ON") {
      filt.tcp_nonce = true;
    } else if (value == "off" | value == "OFF") {
      filt.tcp_nonce = false;
    } else {
      LOG_ERROR("Unknown tcp_nonce value.\n");
      return 1;
    }
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_cwr
  if (key == "tcp_cwr") {
    if (value == "on" | value == "ON") {
      filt.tcp_cwr = true;
    } else if (value == "off" | value == "OFF") {
      filt.tcp_cwr = false;
    } else {
      LOG_ERROR("Unknown tcp_cwr value.\n");
      return 1;
    }
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_ece
  if (key == "tcp_ece") {
    if (value == "on" | value == "ON") {
      filt.tcp_ece = true;
    } else if (value == "off" | value == "OFF") {
      filt.tcp_ece = false;
    } else {
      LOG_ERROR("Unknown tcp_ece value.\n");
      return 1;
    }
    cfg.use_tcp = true;
    return 0;
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
    cfg.use_tcp = true;
    return 0;
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
    cfg.use_tcp = true;
    return 0;
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
    cfg.use_tcp = true;
    return 0;
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
    cfg.use_tcp = true;
    return 0;
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
    cfg.use_tcp = true;
    return 0;
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
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_window
  if (key == "tcp_window") {
    int window = std::stoi(value, nullptr, 0);
    if (check_range_u16(window, key)) {
      return 1;
    }
    filt.tcp_window = window;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_check
  if (key == "tcp_check") {
    int check = std::stoi(value, nullptr, 0);
    if (check_range_u16(check, key)) {
      return 1;
    }
    LOG_INFO(
        "TCP checksum is to be rewritten. Repacket doesn't calculate the "
        "right "
        "check sum.\n");
    filt.tcp_check = check;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_urg_ptr
  if (key == "tcp_urg_ptr") {
    int urg_ptr = std::stoi(value, nullptr, 0);
    if (check_range_u16(urg_ptr, key)) {
      return 1;
    }
    filt.tcp_urg_ptr = urg_ptr;
    cfg.use_tcp = true;
    return 0;
  }

  // udp_src
  if (key == "udp_src") {
    int port = std::stoi(value, nullptr, 0);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt.udp_src = port;
    cfg.use_udp = true;
    return 0;
  }

  // udp_dest
  if (key == "udp_dest") {
    int port = std::stoi(value, nullptr, 0);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt.udp_dest = port;
    cfg.use_udp = true;
    return 0;
  }

  // udp_len
  if (key == "udp_len") {
    int len = std::stoi(value, nullptr, 0);
    if (check_range_u16(len, key)) {
      return 1;
    }
    filt.udp_len = len;
    cfg.use_udp = true;
    return 0;
  }

  // udp_check
  if (key == "udp_check") {
    int check = std::stoi(value, nullptr, 0);
    if (check_range_u16(check, key)) {
      return 1;
    }
    LOG_INFO(
        "UDP checksum is to be rewritten. Repacket doesn't calculate the "
        "right "
        "check sum.\n");
    filt.udp_check = check;
    cfg.use_udp = true;
    return 0;
  }

  // icmp_type
  if (key == "icmp_type") {
    int type = std::stoi(value, nullptr, 0);
    if (check_range_u8(type, key)) {
      return 1;
    }
    filt.icmp_type = type;
    cfg.use_icmp = true;
    return 0;
  }

  // icmp_code
  if (key == "icmp_code") {
    int code = std::stoi(value, nullptr, 0);
    if (check_range_u8(code, key)) {
      return 1;
    }
    filt.icmp_code = code;
    cfg.use_icmp = true;
    return 0;
  }

  // icmp_check
  if (key == "icmp_check") {
    int check = std::stoi(value, nullptr, 0);
    if (check_range_u16(check, key)) {
      return 1;
    }
    LOG_INFO(
        "ICMP checksum is to be rewritten. Repacket doesn't calculate the "
        "right "
        "check sum.\n");
    filt.icmp_check = check;
    cfg.use_icmp = true;
    return 0;
  }

  // UNREACHABLE
  LOG_ERROR("Unknown option. Abort execution.\n");
  return 1;
}
