#include "generator.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "base/define/define.h"
#include "base/logger.h"
#include "base/yaml_handler.h"
#include "core/generator/xdp_base.h"

namespace {
// Convert decimal int to hex string.
std::string ConvertDecimalIntToHexString(int dec) {
  if (!dec) {
    return std::string("00");
  }
  std::string hex;
  const char hc = 'a';
  while (dec != 0) {
    int d = dec & 15;
    if (d < 10) {
      hex.insert(hex.begin(), d + '0');
    } else {
      hex.insert(hex.begin(), d - 10 + hc);
    }
    dec >>= 4;
  }
  if (hex.length() == 1) {
    return "0" + hex;
  } else {
    return hex;
  }
}

// Convert String ip address to hex string.
std::string ConvertIPAddressToHexString(const std::string& address) {
  std::string::size_type pos;
  std::string splitter = ".";
  std::string subpart;
  std::string hex;
  // TODO: Rethinking!
  std::string str_address = address;
  for (int i = 0; i < 4; i++) {
    pos = str_address.find(splitter);
    subpart = str_address.substr(0, pos);
    hex = ConvertDecimalIntToHexString(stoi(subpart)) + hex;
    str_address.erase(0, pos + splitter.size());
  }
  return "0x" + hex;
}

}  // namespace

Generator::Generator(const std::string& yaml_filepath,
                     const std::string& output_filepath)
    : yaml_filepath_(yaml_filepath),
      output_filepath_(output_filepath),
      // TODO: Think whether this causes copy.
      filters_(YamlHandler::ReadYaml(yaml_filepath)) {
  // |filters_.size()| cannot exceed the range of int.
  filter_size_ = static_cast<int>(filters_.size());
}

void Generator::Start() {
  std::string nl = "\n";
  std::string judge_action = *GenerateFromRule().get();

  // include part.
  // TODO: Rethinking!
  std::string include = xdp::include + nl;

  // define part.
  std::string define = xdp::constant(filter_size_) + nl + xdp::struct_datarec +
                       nl + xdp::struct_map + nl + xdp::struct_hdr_cursor;

  // inline function.
  std::string inline_func = xdp::inline_func_stats;

  // xdp section.
  std::string section = xdp::sec_name + xdp::func_name + xdp::func_fix + nl +
                        judge_action + xdp::func_out + xdp::r_bracket + nl;

  // license.
  std::string license = xdp::license;

  xdp_prog_ =
      include + nl + define + nl + inline_func + nl + section + nl + license;
  Write();
  return;
}

void Generator::Write() {
  std::ofstream xdp_file(output_filepath_);
  if (!xdp_file) {
    LOG_ERROR("Cannot open %s.", output_filepath_);
    exit(EXIT_FAIL);
  }
  LOG_INFO("Writing to %s done.", output_filepath_);
  return;
}

std::unique_ptr<std::string> Generator::GenerateFromRule() {
  std::string t = "\t";
  std::string nl = "\n";
  std::string address_checking;
  std::string ipaddr_definition;
  std::string action_codes;

  for (const auto& filter : filters_) {
    int counter = 0;
    int index = filter.priority;

    bool need_tcp = false;
    bool need_udp = false;
    bool need_icmp = false;

    // Generate code which judges action according to the filter.
    // |action_code| is the judging code for one filter.
    std::string action_code = t + "// priority " + std::to_string(index) + nl;
    action_code += t + "priority++;" + nl;
    std::string condition;

    // ip_protocol
    if (!filter.ip_protocol.empty()) {
      if (counter) {
        condition += "&& ";
      }
      if (filter.ip_protocol == "ICMP" || filter.ip_protocol == "icmp") {
        condition += "(iph->protocol == IPPROTO_ICMP) ";
        counter++;
      } else if (filter.ip_protocol == "TCP" || filter.ip_protocol == "tcp") {
        condition += "(iph->protocol == IPPROTO_TCP) ";
        counter++;
      } else if (filter.ip_protocol == "UDP" || filter.ip_protocol == "udp") {
        condition += "(iph->protocol == IPPROTO_UDP) ";
        counter++;
      } else {
        LOG_ERROR("Invalid ip_protocol config.");
        exit(EXIT_FAIL);
      }
    }

    // ip_saddr
    if (!filter.ip_saddr.empty()) {
      if (counter) {
        condition += "&& ";
      }
      std::string ip_saddr_x = "ip_saddr" + std::to_string(index);
      condition += "(iph->saddr == " + ip_saddr_x + ") ";
      ipaddr_definition += t + "__u32 " + ip_saddr_x + " = " +
                           ConvertIPAddressToHexString(filter.ip_saddr) + ";" +
                           nl;
      counter++;
    }

    // ip_daddr
    if (!filter.ip_daddr.empty()) {
      if (counter) {
        condition += "&& ";
      }
      std::string ip_daddr_x = "ip_daddr" + std::to_string(index);
      condition += "(iph->daddr == " + ip_daddr_x + ") ";
      ipaddr_definition += t + "__u32 " + ip_daddr_x + " = " +
                           ConvertIPAddressToHexString(filter.ip_daddr) + ";" +
                           nl;
      counter++;
    }

    // ip_ttl_min
    if (filter.ip_ttl_min != -1) {
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->ttl >= " + std::to_string(filter.ip_ttl_min) + ") ";
      counter++;
    }

    // ip_ttl_max
    if (filter.ip_ttl_max != -1) {
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->ttl <= " + std::to_string(filter.ip_ttl_max) + ") ";
      counter++;
    }

    // ip_tot_len_min
    if (filter.ip_tot_len_min != -1) {
      if (counter) {
        condition += "&& ";
      }
      condition += "(bpf_ntohs(iph->tot_len) >= " +
                   std::to_string(filter.ip_tot_len_min) + ") ";
      counter++;
    }

    // ip_tot_len_max
    if (filter.ip_tot_len_max != -1) {
      if (counter) {
        condition += "&& ";
      }
      condition += "(bpf_ntohs(iph->tot_len) <= " +
                   std::to_string(filter.ip_tot_len_max) + ") ";
      counter++;
    }

    // ip_tos
    if (!filter.ip_tos.empty()) {
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->tos == " + filter.ip_tos + ") ";
      counter++;
    }

    // icmp_type
    if (filter.icmp_type != -1) {
      need_icmp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(icmph->type == " + std::to_string(filter.icmp_type) + ") ";
      counter++;
    }

    // icmp_code
    if (filter.icmp_code != -1) {
      need_icmp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(icmph->code == " + std::to_string(filter.icmp_code) + ") ";
      counter++;
    }

    // tcp_src
    if (filter.tcp_src != -1) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition +=
          "(bpf_ntohs(tcph->source) == " + std::to_string(filter.tcp_src) +
          ") ";
      counter++;
    }

    // tcp_dst
    if (filter.tcp_dst != -1) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition +=
          "(bpf_ntohs(tcph->dest) == " + std::to_string(filter.tcp_dst) + ") ";
      counter++;
    }

    // tcp_urg
    if (filter.tcp_urg) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(tcph->urg == 0b1) ";
      counter++;
    }

    // tcp_ack
    if (filter.tcp_ack) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(tcph->ack == 0b1) ";
      counter++;
    }

    // tcp_psh
    if (filter.tcp_psh) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(tcph->psh == 0b1) ";
      counter++;
    }

    // tcp_rst
    if (filter.tcp_rst) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(tcph->rst == 0b1) ";
      counter++;
    }

    // tcp_syn
    if (filter.tcp_syn) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(tcph->syn == 0b1) ";
      counter++;
    }

    // tcp_fin
    if (filter.tcp_fin) {
      need_tcp = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(tcph->fin == 0b1) ";
      counter++;
    }

    // udp_src
    if (filter.udp_src != -1) {
      need_udp = true;
      if (counter) {
        condition += "&& ";
      }
      condition +=
          "(bpf_ntohs(udph->source) == " + std::to_string(filter.udp_src) +
          ") ";
      counter++;
    }

    // udp_dst
    if (filter.udp_dst != -1) {
      need_udp = true;
      if (counter) {
        condition += "&& ";
      }
      condition +=
          "(bpf_ntohs(udph->dest) == " + std::to_string(filter.udp_dst) + ") ";
      counter++;
    }

    // Null pointer check.
    if (need_tcp) {
      condition = "(tcph && " + condition + ")";
    } else if (need_udp) {
      condition = "(udph && " + condition + ")";
    } else if (need_icmp) {
      condition = "(icmph && " + condition + ")";
    }

    // if statement
    if (counter == 1) {
      action_code += t + "if " + condition + "{" + nl;
    } else {
      action_code += t + "if (" + condition + ") {" + nl;
    }

    // Create action code.
    switch (filter.action) {
      case Action::Pass:
        action_code += t + t + "goto out;" + nl;
        break;
      case Action::Drop:
        action_code +=
            t + t + "action = XDP_DROP;" + nl + t + t + "goto out;" + nl;
    }
    action_code += t + "}" + nl;

    action_codes += action_code + nl;
  }  // for (const auto& filter : filters_)

  action_codes += t + "priority++;" + nl;

  std::unique_ptr<std::string> code = std::make_unique<std::string>(
      xdp::verify_address + nl + ipaddr_definition + nl + action_codes);
  return code;
}
