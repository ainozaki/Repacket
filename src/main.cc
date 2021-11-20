#include <iostream>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <bpf.h>
#include <libbpf.h>

#include "common/cmdline.h"
#include "common/constant.h"
#include "common/define.h"
#include "controller.h"
#include "loader.h"

int main(int argc, char** argv) {
  // Make a rule of cmdline parser.
  cmdline::parser parser;
  parser.add("unload", 'u', "Unload XDP object from eth1.");
  parser.add<std::string>("sec", 's', "Specify the program SEC to load.", false,
                          "xdp_drop");
  parser.parse(argc, argv);

  struct config cfg = {
      .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
      .ifindex = if_nametoindex(kIfname),
      .ifname = kIfname,
      .filename = kFilename,
      .progsec = progsec,
  };

  Controller controller;

  // Detach XDP object from veth1.
  if (parser.exist("unload")) {
    controller.DetachXDP(cfg);
  }

  // Specify progsec to load.
  if (parser.exist("sec")) {
    cfg.progsec = parser.get<std::string>("sec");
  }

  // Load BPF-ELF file.
  controller.StartLoading(cfg);

  return 0;
}
