#include "generator.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "common/define.h"
#include "common/xdp_base.h"

Action ActionFromString(const std::string action) {
  if (action == "pass") {
    return Action::Pass;
  } else if (action == "drop") {
    return Action::Drop;
  } else {
    std::cout << "action must be \"pass\" or \"drop\"" << std::endl;
    exit(EXIT_FAIL);
  }
}

std::string to_hexString(int val) {
  if (!val)
    return std::string("0");
  std::string str;
  const char hc = 'a';
  while (val != 0) {
    int d = val & 15;
    if (d < 10) {
      str.insert(str.begin(), d + '0');
    } else {
      str.insert(str.begin(), d - 10 + hc);
    }
    val >>= 4;
  }
	if (str.length() == 1){
		return "0" + str;
	}else{
		return str;
	}
}

std::string ConvertIPAddressTo16(std::string& addr) {
  std::string addr16;
  std::string::size_type pos;
  std::string splitter = ".";
  std::string part;
  std::stringstream ss;
  for (int i = 0; i < 4; i++) {
    pos = addr.find(splitter);
    part = addr.substr(0, pos);
    addr16 = to_hexString(stoi(part)) + addr16;
    addr.erase(0, pos + splitter.size());
  }
  return "0x" + addr16;
};

Generator::Generator(const std::string& yaml_file) : yaml_file_(yaml_file) {}

void Generator::Start() {
  ReadYaml();
}

void Generator::ReadYaml() {
  const YAML::Node& yaml_policies = YAML::LoadFile(yaml_file_);
  int priority = 0;
  for (const auto& yaml_policy : yaml_policies) {
    Policy policy;
    policy.priority = priority;
    if (!yaml_policy["action"]) {
      std::cout << "rule must have action value." << std::endl;
    }
    policy.action = ActionFromString(yaml_policy["action"].as<std::string>());
    if (yaml_policy["port"]) {
      policy.port = yaml_policy["port"].as<int>();
    }
    if (yaml_policy["ip_address"]) {
      policy.ip_address = yaml_policy["ip_address"].as<std::string>();
    }
    if (yaml_policy["protocol"]) {
      policy.protocol = yaml_policy["protocol"].as<std::string>();
    }
    policies_.push_back(policy);
    priority++;
  }
  Construct();
}

std::unique_ptr<std::string> Generator::CreateFromPolicy() {
  std::string t = "\t";
  std::string nl = "\n";
  std::string verify;
  std::string action_decition;
  std::string inline__filter_addr;
  std::string ipaddr_definition;
  bool need_ip_parse = false;

  for (const auto& policy : policies_) {
    int condition_counter = 0;
    int index = policy.priority;
    std::string prog;
    prog += t + "// priority " + std::to_string(index) + nl;

    // Create condition code.
    std::string condition;
    // protocol
    if (!policy.protocol.empty()) {
      if (policy.protocol == "ICMP" || policy.protocol == "icmp" ||
          policy.protocol == "Icmp") {
        need_ip_parse = true;
        condition += condition_counter ? "&& (iph->protocol == IPPROTO_ICMP) "
                                       : "(iph->protocol == IPPROTO_ICMP) ";
        condition_counter++;
      } else if (policy.protocol == "TCP" || policy.protocol == "tcp") {
        need_ip_parse = true;
        condition += condition_counter ? "&& (iph->protocol == IPPROTO_TCP) "
                                       : "(iph->protocol == IPPROTO_TCP) ";
        condition_counter++;
      } else if (policy.protocol == "UDP" || policy.protocol == "udp") {
        need_ip_parse = true;
        condition += condition_counter ? "&& (iph->protocol == IPPROTO_UDP) "
                                       : "(iph->protocol == IPPROTO_UDP) ";
        condition_counter++;
      }
    }

    // ip address
    if (!policy.ip_address.empty()) {
      need_ip_parse = true;
      inline__filter_addr = "filter_addr_" + std::to_string(index);
      condition +=
          condition_counter
              ? "&& (iph->saddr == " + inline__filter_addr + ")"
              : "(iph->saddr == " + inline__filter_addr + ")";
      std::string ipaddr_string = policy.ip_address;
      ipaddr_definition += t + "__u32 " + inline__filter_addr + " = " +
                           ConvertIPAddressTo16(ipaddr_string) + ";" + nl;
      condition_counter++;
    }

    if (condition_counter == 1) {
      prog += t + "if " + condition + "{" + nl;
    } else {
      prog += t + "if (" + condition + ") {" + nl;
    }

    // Create action code.
    switch (policy.action) {
      case Action::Pass:
        prog += t + t + "goto out;" + nl;
        break;
      case Action::Drop:
        prog += t + t + "action = XDP_DROP;" + nl + t + t + "goto out;" + nl;
    }
    prog += t + "}" + nl;
    action_decition += prog + nl;
  }

  // Create verify code.
  if (need_ip_parse) {
    verify += xdp::verify_ip + nl;
  }

  std::unique_ptr<std::string> code = std::make_unique<std::string>(
      verify + ipaddr_definition + nl + action_decition);
  return code;
}

void Generator::Construct() {
  std::string nl = "\n";
  // include
  std::string include = xdp::include + nl + xdp::include_ip;
  // define
  std::string define = xdp::constant + nl + xdp::struct_datarec + nl +
                       xdp::struct_map + nl + xdp::struct_hdr_cursor;
  // inline function
  std::string inline_func = xdp::inline_func_stats;
  // xdp section
  std::string func_made_from_policy = *CreateFromPolicy().get();
  std::string func = xdp::func_name + xdp::func_fix + func_made_from_policy +
                     xdp::func_out + xdp::r_bracket + xdp::nl;
  std::string sec = xdp::sec_name + func;
  // license
  std::string license = xdp::license;

  xdp_prog_ =
      include + nl + define + nl + inline_func + nl + sec + nl + license;
  Write();
}

void Generator::Write() {
  std::ofstream xdp_file("xdp-generated.c");
  if (!xdp_file) {
    std::cerr << "Cannot open xdp-generated.c" << std::endl;
    exit(EXIT_FAIL);
  }
  xdp_file << xdp_prog_ << std::endl;
  std::cout << "Writing to xdp-generated.c done! " << std::endl;
}
