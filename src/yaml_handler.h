#ifndef YAML_HANDLER_H_
#define YAML_HANDLER_H_

#include <string>
#include <vector>

#include "common/define.h"

class YamlHandler {
 public:
  YamlHandler() = default;
  ~YamlHandler() = default;
  YamlHandler(const YamlHandler&) = delete;

  static std::vector<Filter> ReadYaml(const std::string& filepath);
};
#endif
