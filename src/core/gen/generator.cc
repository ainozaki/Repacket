#include "core/gen/generator.h"

#include <cassert>
#include <fstream>
#include <memory>
#include <string>

#include "base/config.h"
#include "base/logger.h"
#include "core/gen/xdp_base.h"

int Gen(const struct config& cfg) {
  std::ofstream file;
  const std::string filename = "xdp-generated-kern.c";
  int err;

  file.open(filename, std::ios_base::out);
  if (!file) {
    LOG_ERROR("Err: cannot open xdp-generated-kern.c\n");
    return 1;
  }

  // Generate XDP program.
  file << include;
  file << define_struct;
  file << sec_base_f;
  file << action_base;

  switch (cfg.run_mode) {
    case RunMode::FILTER:
      LOG_INFO("FILTER mode.\n");
      file << filter_base_f;
      file << FilteringStatement(cfg);
      file << filter_base_b;
      break;
    case RunMode::REWRITE:
      LOG_INFO("REWRITE mode.\n");
      file << rewrite_base_f;
      file << RewriteFilteringStatement(cfg);
      file << rewrite_base_m;
      file << RewriteStatement(cfg);
      file << rewrite_base_b;
      break;
    default:
      // case DUMPALL
      LOG_INFO("DUMPALL mode.\n");
      break;
  }
  file << sec_base_b;
  file << license;

  file.close();

  if (Compile()) {
    LOG_ERROR("Err while compiling xdp-generated-kern.c\n");
    return 1;
  }
  return 0;
}

int Compile() {
  // compile XDP code using clang.
  int err;
  err = system(
      "clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../deps/include/ -I../deps/include/bpf \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o xdp-generated-kern.ll xdp-generated-kern.c");
  if (err) {
    LOG_ERROR("Err cannot compile\n");
    return 1;
  }

  err = system(
      "llc -march=bpf -filetype=obj -o xdp-generated-kern.o "
      "xdp-generated-kern.ll");
  if (err) {
    LOG_ERROR("Err cannot llc\n");
    return 1;
  }

  LOG_INFO("Success: Compile completed.\n");
  return 0;
}

std::string FilteringStatement(const struct config& cfg) {
  assert(cfg.filter.has_value());
  std::string s;
  const struct filter filter = cfg.filter.value();
  // If config has filtering attributes, convert them into string.
  if (filter.udp_dest) {
    s = "udph && udph->dest==";
    s += std::to_string(filter.udp_dest);
  }
  return s;
}

std::string RewriteFilteringStatement(const struct config& cfg) {
  assert(cfg.filter.has_value());
  std::string s;
  const struct filter filter = cfg.filter.value();
  // If config has filtering attributes, convert them into string.
  if (filter.udp_dest) {
    s = "udph";
  }
  return s;
}

std::string RewriteStatement(const struct config& cfg) {
  assert(cfg.filter.has_value());
  std::string s;
  const struct filter filter = cfg.filter.value();
  if (filter.udp_dest) {
    s = "udph->dest==";
    s += std::to_string(filter.udp_dest);
    s += ";";
  }
  return s;
}
