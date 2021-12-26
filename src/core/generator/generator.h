#ifndef GENERATOR_H_
#define GENERATOR_H_

#include <memory>
#include <string>
#include <vector>

#include "base/define/define.h"

class Generator {
 public:
  Generator(const std::string& yaml_filepath,
            const std::string& output_filepath);
  ~Generator() = default;
  Generator(const Generator&) = delete;

  // Interface function to start generating XDP code.
  void Start();

 private:
  // Generate code dinamically from rule specified at |yaml_filepath_|.
  std::unique_ptr<std::string> GenerateFromRule();

  // Write XDP program to |output_filepath_|.
  void Write();

  // |filter_size_| is one larger than the entry size of rules.
  // This is because filter0 is prepared for packets that doesn't fit the rules.
  int filter_size_;

  std::string xdp_prog_;

  std::string yaml_filepath_;

  std::string output_filepath_;

  std::vector<Filter> filters_;
};

#endif  // GENERATOR_H_
