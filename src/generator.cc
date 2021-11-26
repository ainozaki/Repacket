#include "generator.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "common/define.h"
#include "common/xdp_base.h"

Generator::Generator(const std::string& yaml_file) : yaml_file_(yaml_file) {}

void Generator::Start() {
  ReadYaml();
}

void Generator::ReadYaml() {
  YAML::Node yaml = YAML::LoadFile(yaml_file_);
  if (yaml["access"]) {
    const YAML::Node& yaml_access_policies = yaml["access"];
    for (const auto& yaml_access_policy : yaml_access_policies) {
      Policy policy;
      if (!yaml_access_policy["priority"]) {
        std::cout << "Policy must have priority value." << std::endl;
        exit(EXIT_FAIL);
      }
      policy.priority = yaml_access_policy["priority"].as<int>();
      if (yaml_access_policy["port"]) {
        policy.port = yaml_access_policy["port"].as<int>();
      }
      if (yaml_access_policy["ip_address"]) {
        policy.ip_address = yaml_access_policy["ip_address"].as<std::string>();
      }
      if (yaml_access_policy["protocol"]) {
        policy.protocol = yaml_access_policy["protocol"].as<std::string>();
      }
      access_policies_.push_back(policy);
    }
  }
  if (yaml["deny"]) {
    const YAML::Node& yaml_deny_policies = yaml["deny"];
    for (const auto& yaml_deny_policy : yaml_deny_policies) {
      Policy deny_policy;
      if (!yaml_deny_policy["priority"]) {
        std::cout << "Policy must have priority value." << std::endl;
        exit(EXIT_FAIL);
      }
      deny_policy.priority = yaml_deny_policy["priority"].as<int>();
      if (yaml_deny_policy["port"]) {
        deny_policy.port = yaml_deny_policy["port"].as<int>();
      }
      if (yaml_deny_policy["ip_address"]) {
        deny_policy.ip_address =
            yaml_deny_policy["ip_address"].as<std::string>();
      }
      if (yaml_deny_policy["protocol"]) {
        deny_policy.protocol = yaml_deny_policy["protocol"].as<std::string>();
      }
      deny_policies_.push_back(deny_policy);
    }
  }
  Construct();
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
  std::string func_rule = xdp::func_rule;
  std::string func = xdp::func_name + xdp::func_fix + func_rule +
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
