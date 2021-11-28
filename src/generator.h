#ifndef GENERATOR_H_
#define GENERATOR_H_

#include <memory>
#include <string>
#include <vector>

#include "common/define.h"

class Generator {
 public:
  Generator(const std::string& file);
  ~Generator() = default;
  Generator(const Generator&) = delete;

  void Start();

  std::vector<Policy> policies() { return policies_; }

 private:
  // Read yaml file.
  void ReadYaml();

  // Generate variable code from Policy.
  std::unique_ptr<std::string> CreateFromPolicy();

  // Construct XDP program.
  void Construct();

  // Write XDP program to file.
  void Write();

  std::string xdp_prog_;

  std::string yaml_file_;

  std::vector<Policy> policies_;
};

#endif  // GENERATOR_H_
