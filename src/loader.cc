#include "loader.h"

#include <iostream>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf.h>
#include <libbpf.h>

#include "cmdline.h"
#include "common/common_kern_user.h"
#include "define.h"

struct bpf_object* Loader::LoadAndAttach(const struct config& cfg) {
  int prog_fd = -1;
  struct bpf_object* bpf_obj;
  struct bpf_program* bpf_prog;

  // Load the BPF-ELF file.
  std::cout << "Loading XDP-ELF file..." << std::endl;
  int err = bpf_prog_load(cfg.filename, BPF_PROG_TYPE_XDP, &bpf_obj, &prog_fd);
  if (err) {
    std::cout << "ERR: loading BPF-OBJ file." << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  // Find the selected prog section.
  bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg.progsec.c_str());
  if (!bpf_prog) {
    std::cout << "ERR: finding prog sec: " << cfg.progsec << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  // Find the correspond FD.
  prog_fd = bpf_program__fd(bpf_prog);
  if (prog_fd <= 0) {
    std::cout << "ERR: bpf_program__fd" << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  // Attach the FD to the interface `cfg.ifname`.
  std::cout << "Attaching to an interface..." << std::endl;
  err = bpf_set_link_xdp_fd(cfg.ifindex, prog_fd, cfg.xdp_flags);
  if (err) {
    std::cout << "ERR: attaching XDP." << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  std::cout << "Success: loading BPF and attach XDP." << std::endl;
  return bpf_obj;
}

void Loader::Detach(int ifindex, __u32 xdp_flags) {
  int err;
  std::cout << "Detaching XDP..." << std::endl;
  if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
    std::cout << "ERR: detach xdp object failed." << std::endl;
    exit(EXIT_FAIL_XDP);
  }
  std::cout << "Success: detach XDP pbject." << std::endl;
  exit(EXIT_OK);
}
