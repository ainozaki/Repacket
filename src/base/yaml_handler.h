#ifndef YAML_HANDLER_H_
#define YAML_HANDLER_H_

#include <memory>
#include <string>
#include <vector>

#include "base/define/define.h"

class YamlHandler {
 public:
  YamlHandler() = default;
  ~YamlHandler() = default;
  YamlHandler(const YamlHandler&) = delete;

  static std::vector<Filter> ReadYaml(const std::string& filepath);

  // Read moctok.yaml and extract Action field.
  // Return values are ordered in filtering priority.
  static std::vector<Action> ReadYamlAndGetActions();

  static void StringToFilter(const std::string& key,
                             const std::string& value,
                             std::shared_ptr<Filter> policy);
};
#endif
