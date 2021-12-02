#include <linux/if_link.h>
#include <net/if.h>

#include <string>

#include <cmdline.h>

#include "common/define.h"
#include "controller.h"

namespace {
std::string kBpfFilepath = "xdp-generated.o";
std::string kIfname = "eth1";
std::string kSec = "xdp_generated";
}  // namespace

int main(int argc, char** argv) {
  // Make a rule of cmdline parser.
  cmdline::parser parser;
  parser.add<std::string>("gen", 'g',
                          "Generate XDP program from specified yaml filed.",
                          false, "access.yaml");
  parser.add<std::string>("filepath", 'f', "Specify the BPF filepath.", false,
                          "xdp-generated.o");
  parser.add<std::string>("interface", 'i', "Specify the interface.", false,
                          "eth1");
  parser.add<std::string>("sec", 's', "Specify the program section.", false,
                          "xdp_drop");
  parser.add("unload", 'u', "Unload XDP program from interface.");
  parser.add("help", 'h', "Print usage.");

  if (!parser.parse(argc, argv) || parser.exist("help")) {
    std::cerr << parser.error_full() << parser.usage();
    return 0;
  }

  struct config cfg = {
      .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
      // TODO: Remove ifindex from cfg.
      .ifindex = if_nametoindex(kIfname.c_str()),
      .ifname = parser.exist("interface") ? parser.get<std::string>("interface")
                                          : kIfname,
      .bpf_filepath = parser.exist("filepath")
                          ? parser.get<std::string>("filepath")
                          : kBpfFilepath,
      .progsec = parser.exist("sec") ? parser.get<std::string>("sec") : kSec,
      .unload = parser.exist("unload"),
      .generate = parser.exist("gen"),
      .yaml_filepath =
          parser.exist("gen") ? parser.get<std::string>("gen") : "",
  };

  Controller controller(cfg);
  return 0;
}
