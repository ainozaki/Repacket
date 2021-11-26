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

  void Start();

  std::vector<Policy> access_policies() { return access_policies_; }
  std::vector<Policy> deny_policies() { return deny_policies_; }

 private:
  // Read yaml file.
  void ReadYaml();

  // Construct XDP program.
  void Construct();

  // Write XDP program to file.
  void Write();

  std::string xdp_prog_;

  std::string yaml_file_;

  std::vector<Policy> access_policies_;
  std::vector<Policy> deny_policies_;
};

#endif  // GENERATOR_H_
