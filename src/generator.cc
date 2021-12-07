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
      policies_(YamlHandler::ReadYaml(yaml_filepath)) {
  Construct();
}

Generator::~Generator() {
  std::clog << "Generator destructor" << std::endl;
}

std::unique_ptr<std::string> Generator::CreateFromPolicy() {
  std::string t = "\t";
  std::string nl = "\n";
  std::string address_checking;
  std::string ipaddr_definition;
  std::string action_codes;
  bool need_ip_parse = false;

  for (const auto& policy : policies_) {
    int counter = 0;
    int index = policy.priority;

    // Generate code which judges action according to the policy.
    // |action_code| is the judging code for one policy.
    std::string action_code = t + "// priority " + std::to_string(index) + nl;
    std::string condition;

    // ip_protocol
    if (!policy.ip_protocol.empty()) {
      if (counter) {
        condition += "&& ";
      }
      if (policy.ip_protocol == "ICMP" || policy.ip_protocol == "icmp" ||
          policy.ip_protocol == "Icmp") {
        need_ip_parse = true;
        condition += "(iph->protocol == IPPROTO_ICMP) ";
        counter++;
      } else if (policy.ip_protocol == "TCP" || policy.ip_protocol == "tcp") {
        need_ip_parse = true;
        condition += "(iph->protocol == IPPROTO_TCP) ";
        counter++;
      } else if (policy.ip_protocol == "UDP" || policy.ip_protocol == "udp") {
        need_ip_parse = true;
        condition += "(iph->protocol == IPPROTO_UDP) ";
        counter++;
      }
    }

    // ip_saddr
    if (!policy.ip_saddr.empty()) {
      need_ip_parse = true;
      if (counter) {
        condition += "&& ";
      }
      std::string ip_saddr_x = "ip_saddr" + std::to_string(index);
      condition += "(iph->saddr == " + ip_saddr_x + ") ";
      ipaddr_definition += t + "__u32 " + ip_saddr_x + " = " +
                           ConvertIPAddressToHexString(policy.ip_saddr) + ";" +
                           nl;
      counter++;
    }

    // ip_daddr
    if (!policy.ip_daddr.empty()) {
      need_ip_parse = true;
      if (counter) {
        condition += "&& ";
      }
      std::string ip_daddr_x = "ip_daddr" + std::to_string(index);
      condition += "(iph->daddr == " + ip_daddr_x + ") ";
      ipaddr_definition += t + "__u32 " + ip_daddr_x + " = " +
                           ConvertIPAddressToHexString(policy.ip_daddr) + ";" +
                           nl;
      counter++;
    }

    // ip_ttl_min
    if (policy.ip_ttl_min != -1) {
      need_ip_parse = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->ttl < " + std::to_string(policy.ip_ttl_min) + ") ";
      counter++;
    }

    // ip_ttl_max
    if (policy.ip_ttl_max != -1) {
      need_ip_parse = true;
      if (counter) {
        condition += "&& ";
      }
      condition += "(iph->ttl > " + std::to_string(policy.ip_ttl_max) + ") ";
      counter++;
    }

    // if statement
    if (counter == 1) {
      action_code += t + "if " + condition + "{" + nl;
    } else {
      action_code += t + "if (" + condition + ") {" + nl;
    }

    // Create action code.
    switch (policy.action) {
      case Action::Pass:
        action_code += t + t + "goto out;" + nl;
        break;
      case Action::Drop:
        action_code +=
            t + t + "action = XDP_DROP;" + nl + t + t + "goto out;" + nl;
    }
    action_code += t + "}" + nl;

    action_codes += action_code + nl;
  }  // for (const auto& policy : policies_)

  // Create verify code.
  if (need_ip_parse) {
    address_checking += xdp::verify_ip + nl;
  }

  std::unique_ptr<std::string> code = std::make_unique<std::string>(
      address_checking + ipaddr_definition + nl + action_codes);
  return code;
}

void Generator::Construct() {
  std::string nl = "\n";

  // include part.
  std::string include = xdp::include + nl + xdp::include_ip;

  // define part.
  std::string define = xdp::constant + nl + xdp::struct_datarec + nl +
                       xdp::struct_map + nl + xdp::struct_hdr_cursor;

  // inline function.
  std::string inline_func = xdp::inline_func_stats;

  // xdp section.
  std::string judge_action = *CreateFromPolicy().get();
  std::string section = xdp::sec_name + xdp::func_name + xdp::func_fix +
                        judge_action + xdp::func_out + xdp::r_bracket + xdp::nl;

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
