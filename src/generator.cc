#include "generator.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "common/define.h"
#include "common/xdp_base.h"
#include "yaml_handler.h"

namespace {
// Convert decimal int to hex string.
std::string ConvertDecimalIntToHexString(int dec) {
  if (!dec) {
    return std::string("0");
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

Generator::Generator(const std::string& yaml_filepath)
    : yaml_filepath_(yaml_filepath),
      // TODO: Think whether this causes copy.
      filters_(YamlHandler::ReadYaml(yaml_filepath)) {
  Construct();
}

Generator::~Generator() {
  std::clog << "Generator destructor" << std::endl;
}

std::unique_ptr<std::string> Generator::CreateFromFilter() {
  std::string t = "\t";
  std::string nl = "\n";
  std::string address_checking;
  std::string ipaddr_definition;
  std::string action_codes;

  for (const auto& filter : filters_) {
    int counter = 0;
    int index = filter.priority;

    // Generate code which judges action according to the filter.
    // |action_code| is the judging code for one filter.
    std::string action_code = t + "// priority " + std::to_string(index) + nl;
    std::string condition;

    // ip_protocol
    if (!filter.ip_protocol.empty()) {
      need_ip_parse_ = true;
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
      }
    }

    // ip_saddr
    if (!filter.ip_saddr.empty()) {
      need_ip_parse_ = true;
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
      need_ip_parse_ = true;
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
      need_ip_parse_ = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->ttl < " + std::to_string(filter.ip_ttl_min) + ") ";
      counter++;
    }

    // ip_ttl_max
    if (filter.ip_ttl_max != -1) {
      need_ip_parse_ = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->ttl > " + std::to_string(filter.ip_ttl_max) + ") ";
      counter++;
    }

    // ip_tot_len_min
    if (filter.ip_tot_len_min != -1) {
      need_ip_parse_ = true;
      if (counter) {
        condition += "&& ";
      }
      condition +=
          "(iph->tot_len < " + std::to_string(filter.ip_tot_len_min) + ") ";
      counter++;
    }

    // ip_tot_len_min
    if (filter.ip_tot_len_max != -1) {
      need_ip_parse_ = true;
      if (counter) {
        condition += "&& ";
      }
      condition +=
          "(iph->tot_len > " + std::to_string(filter.ip_tot_len_max) + ") ";
      counter++;
    }

    // ip_tos
    if (!filter.ip_tos.empty()) {
      need_ip_parse_ = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->tos == " + filter.ip_tos + ") ";
      counter++;
    }

    // icmp_type
    if (filter.icmp_type != -1) {
      need_icmp_parse_ = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(icmph->type == " + std::to_string(filter.icmp_type) + ") ";
      counter++;
    }

    // icmp_code
    if (filter.icmp_code != -1) {
      need_icmp_parse_ = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(icmph->code == " + std::to_string(filter.icmp_code) + ") ";
      counter++;
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

  // Create verify code.
  if (need_ip_parse_ || need_icmp_parse_) {
    address_checking += xdp::verify_ip + nl;
  }
  if (need_icmp_parse_) {
    address_checking += xdp::verify_icmp + nl;
  }

  std::unique_ptr<std::string> code = std::make_unique<std::string>(
      address_checking + ipaddr_definition + nl + action_codes);
  return code;
}

void Generator::Construct() {
  std::string nl = "\n";
  std::string judge_action = *CreateFromFilter().get();
  std::cerr << "CreateFromFilter finished" << std::endl;

  // include part.
  // Must call CreateFromFilter() first to use need_x_parse_.
  std::string include = xdp::include + nl;

  if (need_ip_parse_ || need_icmp_parse_) {
    include += xdp::include_ip + nl;
  }
  if (need_icmp_parse_) {
    include += xdp::include_icmp + nl;
  }

  // define part.
  std::string define = xdp::constant + nl + xdp::struct_datarec + nl +
                       xdp::struct_map + nl + xdp::struct_hdr_cursor;

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
    std::cerr << "Cannot open " << output_filepath_ << std::endl;
    exit(EXIT_FAIL);
  }
  xdp_file << xdp_prog_ << std::endl;
  std::cerr << "Writing to " << output_filepath_ << " done!" << std::endl;
  return;
}
