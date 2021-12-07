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
  std::string action_decition;
  std::string ipaddr_definition;
  bool need_ip_parse = false;

  for (const auto& policy : policies_) {
    int condition_counter = 0;
    int index = policy.priority;

    // Create condition code reflecting policy.
    // |policy_code| represents for one policy.
    std::string policy_code = t + "// priority " + std::to_string(index) + nl;
    std::string condition;

    // protocol
    if (!policy.ip_protocol.empty()) {
      if (policy.ip_protocol == "ICMP" || policy.ip_protocol == "icmp" ||
          policy.ip_protocol == "Icmp") {
        need_ip_parse = true;
        condition += condition_counter ? "&& (iph->protocol == IPPROTO_ICMP) "
                                       : "(iph->protocol == IPPROTO_ICMP) ";
        condition_counter++;
      } else if (policy.ip_protocol == "TCP" || policy.ip_protocol == "tcp") {
        need_ip_parse = true;
        condition += condition_counter ? "&& (iph->protocol == IPPROTO_TCP) "
                                       : "(iph->protocol == IPPROTO_TCP) ";
        condition_counter++;
      } else if (policy.ip_protocol == "UDP" || policy.ip_protocol == "udp") {
        need_ip_parse = true;
        condition += condition_counter ? "&& (iph->protocol == IPPROTO_UDP) "
                                       : "(iph->protocol == IPPROTO_UDP) ";
        condition_counter++;
      }
    }

    // ip_saddr conversion.
    if (!policy.ip_saddr.empty()) {
      need_ip_parse = true;
      std::string ip_saddr_x = "ip_saddr" + std::to_string(index);
      condition += condition_counter ? "&& (iph->saddr == " + ip_saddr_x + ") "
                                     : "(iph->saddr == " + ip_saddr_x + ") ";
      ipaddr_definition += t + "__u32 " + ip_saddr_x + " = " +
                           ConvertIPAddressToHexString(policy.ip_saddr) + ";" +
                           nl;
      condition_counter++;
    }

    // ip_daddr conversion.
    if (!policy.ip_daddr.empty()) {
      need_ip_parse = true;
      std::string ip_daddr_x = "ip_daddr" + std::to_string(index);
      condition += condition_counter ? "&& (iph->daddr == " + ip_daddr_x + ") "
                                     : "(iph->daddr == " + ip_daddr_x + ") ";
      ipaddr_definition += t + "__u32 " + ip_daddr_x + " = " +
                           ConvertIPAddressToHexString(policy.ip_daddr) + ";" +
                           nl;
      condition_counter++;
    }

    // if statement
    if (condition_counter == 1) {
      policy_code += t + "if " + condition + "{" + nl;
    } else {
      policy_code += t + "if (" + condition + ") {" + nl;
    }

    // Create action code.
    switch (policy.action) {
      case Action::Pass:
        policy_code += t + t + "goto out;" + nl;
        break;
      case Action::Drop:
        policy_code +=
            t + t + "action = XDP_DROP;" + nl + t + t + "goto out;" + nl;
    }
    policy_code += t + "}" + nl;

    // |action_decition| is a set of |policy_code|.
    action_decition += policy_code + nl;

  }  // for (const auto& policy : policies_)

  // Create verify code.
  if (need_ip_parse) {
    address_checking += xdp::verify_ip + nl;
  }

  std::unique_ptr<std::string> code = std::make_unique<std::string>(
      address_checking + ipaddr_definition + nl + action_decition);
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
  std::string policy = *CreateFromPolicy().get();
  std::string func = xdp::func_name + xdp::func_fix + policy + xdp::func_out +
                     xdp::r_bracket + xdp::nl;
  std::string sec = xdp::sec_name + func;

  // license.
  std::string license = xdp::license;

  xdp_prog_ =
      include + nl + define + nl + inline_func + nl + sec + nl + license;
  Write();
  return;
}

void Generator::Write() {
  std::ofstream xdp_file("xdp-generated.c");
  if (!xdp_file) {
    std::cerr << "Cannot open xdp-generated.c" << std::endl;
    exit(EXIT_FAIL);
  }
  xdp_file << xdp_prog_ << std::endl;
  std::cerr << "Writing to xdp-generated.c done! " << std::endl;
  return;
}
