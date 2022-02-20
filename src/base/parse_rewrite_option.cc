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
                       struct filter* filt,
                       struct config& cfg) {
  // ip_ver
  if (key == "ip_ver") {
    uint8_t ver = std::stoi(value);
    if (check_range_u4(ver, key)) {
      return 1;
    }
    if (ver != 4) {
      LOG_INFO("Xapture supports only ipv4. Continue.\n");
    }
    filt->ip_ver = ver;
    cfg.use_ip = true;
    return 0;
  }

  // ip_hl
  if (key == "ip_hl") {
    uint8_t hlen = std::stoi(value);
    if (check_range_u4(hlen, key)) {
      return 1;
    }
    filt->ip_hl = hlen;
    cfg.use_ip = true;
    return 0;
  }

  // ip_tos
  if (key == "ip_tos") {
    // Type of Service is entered as a hex value.
    uint16_t tos = std::stoi(value, nullptr, 8);
    if (check_range_u8(tos, key)) {
      return 1;
    }
    filt->ip_tos = tos;
    cfg.use_ip = true;
    return 0;
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
    filt->ip_tot_len = len;
    cfg.use_ip = true;
    return 0;
  }

  // ip_id
  if (key == "ip_id") {
    uint32_t id = std::stoi(value);
    if (check_range_u32(id, key)) {
      return 1;
    }
    filt->ip_id = id;
    cfg.use_ip = true;
    return 0;
  }

  // ip_ttl
  if (key == "ip_ttl") {
    uint16_t ttl = std::stoi(value);
    if (check_range_u16(ttl, key)) {
      return 1;
    }
    filt->ip_ttl = ttl;
    cfg.use_ip = true;
    return 0;
  }

  // ip_protocol
  if (key == "ip_protocol") {
    uint16_t protocol = std::stoi(value);
    if (check_range_u8(protocol, key)) {
      return 1;
    }
    filt->ip_protocol = protocol;
    cfg.use_ip = true;
    return 0;
  }

  // ip_check
  if (key == "ip_check") {
    uint32_t check = std::stoi(value);
    if (check_range_u16(check, key)) {
      return 1;
    }
    filt->ip_check = check;
    LOG_INFO(
        "Ip checksum is to be rewritten. Xapture doesn't calculate the "
        "right "
        "check sum.\n");
    cfg.use_ip = true;
    return 0;
  }

  // ip_src
  if (key == "ip_src") {
    uint32_t ipaddr = ipaddr_from_string(value + ".");
    filt->ip_src = value;
    cfg.use_ip = true;
    return 0;
  }

  // tcp_src
  if (key == "tcp_src") {
    uint32_t port = std::stoi(value);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt->tcp_src = port;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_dest
  if (key == "tcp_dest") {
    uint32_t port = std::stoi(value);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt->tcp_dest = port;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_seq
  if (key == "tcp_seq") {
    uint64_t seq = std::stoi(value);
    if (check_range_u32(seq, key)) {
      return 1;
    }
    filt->tcp_seq = seq;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_ack_seq
  if (key == "tcp_ack_seq") {
    uint64_t ack_seq = std::stoi(value);
    if (check_range_u32(ack_seq, key)) {
      return 1;
    }
    filt->tcp_ack_seq = ack_seq;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_doff
  if (key == "tcp_doff") {
    uint8_t doff = std::stoi(value);
    if (check_range_u4(doff, key)) {
      return 1;
    }
    filt->tcp_doff = doff;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_res1
  if (key == "tcp_res1") {
    uint8_t res1 = std::stoi(value);
    if (check_range_u4(res1, key)) {
      return 1;
    }
    filt->tcp_res1 = res1;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_res2
  if (key == "tcp_res2") {
    uint8_t res2 = std::stoi(value);
    // res2 field is 2 bit.
    if (res2<0 | res2> 3) {
      return 1;
    }
    filt->tcp_res2 = res2;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_urg
  if (key == "tcp_urg") {
    if (value == "on" | value == "ON") {
      filt->tcp_urg = true;
    } else if (value == "off" | value == "OFF") {
      filt->tcp_urg = false;
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
      filt->tcp_ack = true;
    } else if (value == "off" | value == "OFF") {
      filt->tcp_ack = false;
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
      filt->tcp_psh = true;
    } else if (value == "off" | value == "OFF") {
      filt->tcp_psh = false;
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
      filt->tcp_rst = true;
    } else if (value == "off" | value == "OFF") {
      filt->tcp_rst = false;
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
      filt->tcp_syn = true;
    } else if (value == "off" | value == "OFF") {
      filt->tcp_syn = false;
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
      filt->tcp_fin = true;
    } else if (value == "off" | value == "OFF") {
      filt->tcp_fin = false;
    } else {
      LOG_ERROR("Unknown tcp_urg value.\n");
      return 1;
    }
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_window
  if (key == "tcp_window") {
    uint32_t window = std::stoi(value);
    if (check_range_u16(window, key)) {
      return 1;
    }
    filt->tcp_window = window;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_
  if (key == "tcp_check") {
    uint32_t check = std::stoi(value);
    if (check_range_u16(check, key)) {
      return 1;
    }
    LOG_INFO(
        "TCP checksum is to be rewritten. Xapture doesn't calculate the "
        "right "
        "check sum.\n");
    filt->tcp_check = check;
    cfg.use_tcp = true;
    return 0;
  }

  // tcp_urg_ptr
  if (key == "tcp_urg_ptr") {
    uint32_t urg_ptr = std::stoi(value);
    if (check_range_u16(urg_ptr, key)) {
      return 1;
    }
    filt->tcp_urg_ptr = urg_ptr;
    cfg.use_tcp = true;
    return 0;
  }

  // udp_src
  if (key == "udp_src") {
    uint32_t port = std::stoi(value);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt->udp_src = port;
    cfg.use_udp = true;
    return 0;
  }

  // udp_dest
  if (key == "udp_dest") {
    uint32_t port = std::stoi(value);
    if (check_range_u16(port, key)) {
      return 1;
    }
    filt->udp_dest = port;
    cfg.use_udp = true;
    return 0;
  }

  // udp_len
  if (key == "udp_len") {
    uint32_t len = std::stoi(value);
    if (check_range_u16(len, key)) {
      return 1;
    }
    filt->udp_len = len;
    cfg.use_udp = true;
    return 0;
  }

  // udp_check
  if (key == "udp_check") {
    uint32_t check = std::stoi(value);
    if (check_range_u16(check, key)) {
      return 1;
    }
    LOG_INFO(
        "UDP checksum is to be rewritten. Xapture doesn't calculate the "
        "right "
        "check sum.\n");
    filt->udp_check = check;
    cfg.use_udp = true;
    return 0;
  }

  // UNREACHABLE
  LOG_ERROR("Unknown option. Abort execution.\n");
  return 1;
}
