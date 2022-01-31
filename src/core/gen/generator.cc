#include "core/gen/generator.h"

#include <cassert>
#include <fstream>
#include <memory>
#include <string>

#include "base/config.h"
#include "base/logger.h"
#include "core/gen/xdp_base.h"

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
  if (filter.ip_src != "" | filter.ip_ttl | filter.ip_protocol |
      filter.ip_tot_len) {
    s = "iph";
  } else if (filter.tcp_dest | filter.tcp_src | filter.tcp_urg |
             filter.tcp_ack | filter.tcp_psh | filter.tcp_rst | filter.tcp_syn |
             filter.tcp_fin) {
    s = "tcph";
  } else if (filter.udp_dest | filter.udp_src) {
    s = "udph";
  }
  return s;
}

std::string RewriteStatement(const struct config& cfg) {
  assert(cfg.filter.has_value());
  std::string s;
  const struct filter filter = cfg.filter.value();
  if (filter.ip_src != "") {
    s = "iph->saddr=bpf_htons(";
    s += ConvertIPAddressToHexString(filter.ip_src);
    s += ")";
  } else if (filter.ip_ttl) {
    s = "iph->ttl=";
    s += std::to_string(filter.ip_ttl);
  } else if (filter.ip_protocol) {
    s = "iph->proto=";
    s += std::to_string(filter.ip_protocol);
  } else if (filter.ip_tot_len) {
    s = "iph->tot_len=";
    s += std::to_string(filter.ip_tot_len);
  } else if (filter.tcp_urg) {
    s = "tcph->urg=1";
  } else if (filter.tcp_ack) {
    s = "tcph->ack=1";
  } else if (filter.tcp_psh) {
    s = "tcph->psh=1";
  } else if (filter.tcp_rst) {
    s = "tcph->rst=1";
  } else if (filter.tcp_syn) {
    s = "tcph->syn=1";
  } else if (filter.tcp_fin) {
    s = "tcph->fin=1";
  } else if (filter.tcp_dest) {
    s = "tcph->dest=bpf_htons(";
    s += std::to_string(filter.tcp_dest);
    s += ")";
  } else if (filter.tcp_src) {
    s = "tcph->source=bpf_htons(";
    s += std::to_string(filter.tcp_src);
    s += ")";
  } else if (filter.udp_dest) {
    s = "udph->dest=bpf_htons(";
    s += std::to_string(filter.udp_dest);
    s += ")";
  } else if (filter.udp_src) {
    s = "udph->source=bpf_htons(";
    s += std::to_string(filter.udp_src);
    s += ")";
  }
  s += ";";
  return s;
}
