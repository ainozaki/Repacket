#include "core/gen/gen_controller.h"

#include <cassert>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "base/config.h"
#include "base/logger.h"
#include "core/gen/gen_dynamic.h"
#include "core/gen/gen_static.h"

namespace {
std::string ConvertDecimalIntToHexString(int dec) {
  if (!dec) {
    return std::string("00");
  }
  std::string hex;
  const char hc = 'a';
  while (dec != 0) {
    int d = dec & 15;
    if (d < 10) {
      hex.insert(hex.begin(), d + '0');
    } else {
      hex.insert(hex.begin(), d - 10 + hc);
    }
    dec >>= 4;
  }
  if (hex.length() == 1) {
    return "0" + hex;
  } else {
    return hex;
  }
}

// Convert String ip address to hex string.
std::string ConvertIPAddressToHexString(const std::string& address) {
  std::string::size_type pos;
  std::string splitter = ".";
  std::string subpart;
  std::string hex;
  // TODO: Rethinking!
  std::string str_address = address;
  for (int i = 0; i < 4; i++) {
    pos = str_address.find(splitter);
    subpart = str_address.substr(0, pos);
    hex = ConvertDecimalIntToHexString(stoi(subpart)) + hex;
    str_address.erase(0, pos + splitter.size());
  }
  return "0x" + hex;
}
}  // namespace

int Gen(const struct config& cfg) {
  std::ofstream file;
  const std::string filename = "xdp-generated-kern.c";
  int err;

  file.open(filename, std::ios_base::out);
  if (!file) {
    LOG_ERROR("Err: cannot open xdp-generated-kern.c\n");
    return 1;
  }

  file << include;
  file << define_common;

  // Generate XDP program.
  switch (cfg.run_mode) {
    case RunMode::REWRITE:
      LOG_INFO("REWRITE mode.\n");
      file << define_struct_map;
      file << sec_map_top;
      file << parse_common;
      file << FilteringStatement(cfg);
      file << RewriteStatement(cfg);
      file << sec_map_bottom;
      break;
    default:
      // case DUMPALL
      LOG_INFO("DUMPALL mode.\n");
      break;
  }
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
