#include "controller.h"

#include <string>

#include <bpf.h>
#include <cmdline.h>

#include "common/constant.h"
#include "common/define.h"
#include "generator.h"
#include "loader.h"
#include "map.h"

void Controller::ParseCmdline(int argc, char** argv) {
  // Make a rule of cmdline parser.
  cmdline::parser parser;
  parser.add<std::string>("gen", '\0',
                          "Generate XDP program from specified yaml file.",
                          false, "access.yaml");
  parser.add<std::string>("sec", '\0', "Specify the program SEC to load.",
                          false, "xdp_drop");
  parser.add("unload", 'u', "Unload XDP object from eth1.");
  parser.parse(argc, argv);

  struct config cfg = {
      .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
      .ifindex = if_nametoindex(kIfname),
      .ifname = kIfname,
      .filename = kFilename,
      .progsec = progsec,
  };
  // Specify section to load.
  if (parser.exist("sec")) {
    cfg.progsec = parser.get<std::string>("sec");
  }

  // Generate XDP program from rule.
  if (parser.exist("gen")) {
    std::string rule_file = parser.get<std::string>("gen");
    GenerateXDP(rule_file);
    exit(0);
  }

  // Detach XDP object from veth1.
  if (parser.exist("unload")) {
    DetachXDP(cfg);
  }

  // Load BPF-ELF file.
  StartLoading(cfg);
}

void Controller::DetachXDP(struct config& cfg) {
  loader_.Detach(cfg.ifindex, cfg.xdp_flags);
}

void Controller::GenerateXDP(std::string& file) {
  Generator generator(file);
  generator.StartReadYaml();
}

void Controller::Stats() {
  map_.StatsPoll(map_fd_, &map_info_);
}

void Controller::MapSetup() {
  // Check map info.
  int check_result = map_.CheckMapInfo(map_fd_, &map_info_);
  if (check_result) {
    exit(check_result);
  }
}

void Controller::StartLoading(struct config& cfg) {
  // Load the BPF-ELF object file and attach to an interface.
  struct bpf_object* bpf_obj = loader_.LoadAndAttach(cfg);

  map_fd_ = map_.FindMapFd(bpf_obj, "xdp_stats_map");

  // Setup map.
  MapSetup();

  // Start collecting stats.
  Stats();
}
