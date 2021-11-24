#include "generator.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "common/define.h"

Generator::Generator(const std::string& filename) : filename_(filename) {}

void Generator::StartReadYaml() {
  YAML::Node yaml = YAML::LoadFile(filename_);
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
}
