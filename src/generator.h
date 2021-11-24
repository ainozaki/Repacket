#ifndef GENERATOR_H_
#define GENERATOR_H_

#include <string>
#include <vector>

#include "common/define.h"

class Generator {
 public:
  Generator(const std::string& file);
  ~Generator() = default;
  Generator(const Generator&) = delete;

  // Read yaml file.
  void StartReadYaml();

 private:
  std::string file_;

  std::vector<Policy> access_policies_;
  std::vector<Policy> deny_policies_;
};

#endif  // GENERATOR_H_
