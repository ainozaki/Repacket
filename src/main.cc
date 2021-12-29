#include <linux/if_link.h>
#include <net/if.h>

#include <string>

#include <cmdline.h>

#include "base/define/define.h"
#include "xilter.h"

namespace {
std::string kDefaultYamlFilepath = "xilter.yaml";
std::string kDefaultOutputFilepath = "xdp-generated.c";
std::string kDefaultBpfFilepath = "xdp-generated.o";
std::string kDefaultIfname = "eth1";
std::string kDefaultSec = "xdp_generated";
}  // namespace

int main(int argc, char** argv) {
  // Make a rule of cmdline parser.
  cmdline::parser parser;
  parser.add("gen", 'g', "Generate XDP program.");
  parser.add("attach", 'a', "Attach XDP program.");
  parser.add("detach", 'd', "Detach XDP program.");
  parser.add("stats", 's', "Display filtering stats.");
  parser.add<std::string>("interface", 'i', "Specify interface.", false,
                          kDefaultIfname);
  parser.add<std::string>("bpf", '\0', "BPF filepath.", false,
                          kDefaultBpfFilepath);
  parser.add<std::string>("input", '\0', "Input yaml filepath.", false,
                          kDefaultYamlFilepath);
  parser.add<std::string>("output", '\0', "Output filepath.", false,
                          kDefaultOutputFilepath);
  parser.add<std::string>("sec", '\0',
                          "[Advanced option] Specify program section.", false,
                          kDefaultSec);
  parser.add("help", 'h', "Print usage.");

  // TODO: Limit option combinations.
  if (!parser.parse(argc, argv) || parser.exist("help")) {
    std::cerr << parser.error_full() << parser.usage();
    return 0;
  }

  struct config cfg;
  cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
  // TODO: Remove ifindex from cfg.
  cfg.ifname = parser.exist("interface") ? parser.get<std::string>("interface")
                                         : kDefaultIfname;
  cfg.ifindex = if_nametoindex(cfg.ifname.c_str());
  cfg.bpf_filepath = parser.exist("bpf") ? parser.get<std::string>("bpf")
                                         : kDefaultBpfFilepath;
  cfg.progsec =
      parser.exist("sec") ? parser.get<std::string>("sec") : kDefaultSec;
  cfg.yaml_filepath = parser.exist("input") ? parser.get<std::string>("input")
                                            : kDefaultYamlFilepath;
  cfg.output_filepath = parser.exist("output")
                            ? parser.get<std::string>("output")
                            : kDefaultOutputFilepath;

  if (parser.exist("attach")) {
    cfg.mode = Mode::Attach;
  } else if (parser.exist("detach")) {
    cfg.mode = Mode::Detach;
  } else if (parser.exist("gen")) {
    cfg.mode = Mode::Generate;
  } else if (parser.exist("stats")) {
    cfg.mode = Mode::Stats;
  }

  Xilter xilter(cfg);
  return 0;
}
