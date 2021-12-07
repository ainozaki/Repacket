#include "yaml_handler.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "common/define.h"

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

void StringToPolicy(const std::string& key,
                    const std::string& value,
                    std::shared_ptr<Policy> policy) {
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
  }
}

}  // namespace

// static
std::vector<Policy> YamlHandler::ReadYaml(const std::string& filepath) {
  std::vector<Policy> policies;
  YAML::Node node = YAML::LoadFile(filepath);
  int priority = 0;
  if (node["all"]) {
    YAML::Node all = node["all"];
    for (std::size_t i = 0; i < all.size(); i++) {
      std::shared_ptr<Policy> policy = std::make_shared<Policy>();
      policy->priority = priority;
      for (YAML::const_iterator it = all[i].begin(); it != all[i].end(); ++it) {
        std::string key = it->first.as<std::string>();
        std::string value = it->second.as<std::string>();
        StringToPolicy(key, value, policy);
      }
      policies.push_back(*policy);
      priority++;
    }
  }
  return policies;
}
