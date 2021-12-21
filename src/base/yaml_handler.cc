#include "yaml_handler.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "base/define/define.h"

namespace {
// Convert enum class Action to String.
Action ConvertActionFromString(const std::string& action) {
  if (action == "pass") {
    return Action::Pass;
  } else if (action == "drop") {
    return Action::Drop;
  } else {
    std::cerr << "action must be 'pass' or 'drop'" << std::endl;
    exit(EXIT_FAIL);
  }
}

// Convert string to according ICMP type.
int ConvertIcmpTypeFromString(const std::string& type) {
  if (type == "echo-reply") {
    return 0;
  } else if (type == "unreachable") {
    return 3;
  } else if (type == "redirect") {
    return 5;
  } else if (type == "echo-request") {
    return 8;
  } else if (type == "time-exceeded") {
    return 11;
  } else {
    std::cerr << "ICMP type specified in filter config is invalid."
              << std::endl;
    exit(EXIT_FAIL);
  }
  return -1;
}

// Convert string to bool.
bool ConvertBoolFromString(const std::string& value) {
  if (value == "true") {
    return true;
  } else if (value == "false") {
    return false;
  } else {
    std::cerr << "Unknown value: " << value << std::endl;
    exit(EXIT_FAIL);
  }
  return false;
}

}  // namespace

// static
void YamlHandler::StringToFilter(const std::string& key,
                                 const std::string& value,
                                 std::shared_ptr<Filter> policy) {
  if (key == "action") {
    policy->action = ConvertActionFromString(value);
  } else if (key == "ip_protocol") {
    policy->ip_protocol = value;
  } else if (key == "ip_saddr") {
    policy->ip_saddr = value;
  } else if (key == "ip_daddr") {
    policy->ip_daddr = value;
  } else if (key == "ip_ttl_min") {
    policy->ip_ttl_min = std::stoi(value);
  } else if (key == "ip_ttl_max") {
    policy->ip_ttl_max = std::stoi(value);
  } else if (key == "ip_tot_len_min") {
    policy->ip_tot_len_min = std::stoi(value);
  } else if (key == "ip_tot_len_max") {
    policy->ip_tot_len_max = std::stoi(value);
  } else if (key == "ip_tos") {
    policy->ip_tos = value;
  } else if (key == "icmp_type") {
    policy->icmp_type = ConvertIcmpTypeFromString(value);
  } else if (key == "icmp_code") {
    policy->icmp_code = std::stoi(value);
  } else if (key == "tcp_src") {
    policy->tcp_src = std::stoi(value);
  } else if (key == "tcp_dst") {
    policy->tcp_dst = std::stoi(value);
  } else if (key == "tcp_urg") {
    policy->tcp_urg = ConvertBoolFromString(value);
  } else if (key == "tcp_ack") {
    policy->tcp_ack = ConvertBoolFromString(value);
  } else if (key == "tcp_psh") {
    policy->tcp_psh = ConvertBoolFromString(value);
  } else if (key == "tcp_rst") {
    policy->tcp_rst = ConvertBoolFromString(value);
  } else if (key == "tcp_syn") {
    policy->tcp_syn = ConvertBoolFromString(value);
  } else if (key == "tcp_fin") {
    policy->tcp_fin = ConvertBoolFromString(value);
  }
}

// static
std::vector<Filter> YamlHandler::ReadYaml(const std::string& filepath) {
  std::vector<Filter> filters;
  // TODO: Why this filepath works?
  YAML::Node node = YAML::LoadFile(filepath);
  int priority = 1;
  if (node["filter"]) {
    YAML::Node filter = node["filter"];
    for (std::size_t i = 0; i < filter.size(); i++) {
      std::shared_ptr<Filter> policy = std::make_shared<Filter>();
      policy->priority = priority;
      for (YAML::const_iterator it = filter[i].begin(); it != filter[i].end();
           ++it) {
        std::string key = it->first.as<std::string>();
        std::string value = it->second.as<std::string>();
        StringToFilter(key, value, policy);
      }
      filters.push_back(*policy);
      priority++;
    }
  }
  return filters;
}

// static
std::vector<Action> YamlHandler::ReadYamlAndGetActions(
    const std::string filepath) {
  std::vector<Action> actions;
  // priority 0 is pass.
  // This is used for exceptional packets.
  actions.push_back(Action::Pass);
  YAML::Node filter = YAML::LoadFile(filepath)["filter"];
  for (std::size_t i = 0; i < filter.size(); i++) {
    std::string action = filter[i]["action"].as<std::string>();
    actions.push_back(ConvertActionFromString(action));
  }
  return actions;
}
