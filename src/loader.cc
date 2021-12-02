#include "loader.h"

#include <cassert>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf.h>
#include <libbpf.h>

#include <cmdline.h>

#include "common/define.h"
#include "controller.h"

Loader::Loader(uint32_t xdp_flags,
               unsigned int ifindex,
               const std::string& ifname,
               const std::string& bpf_filepath,
               const std::string& progsec)
    : xdp_flags_(xdp_flags),
      ifindex_(ifindex),
      ifname_(ifname),
      bpf_filepath_(bpf_filepath),
      progsec_(progsec) {}

Loader::~Loader() {
  std::clog << "Loader destruction" << std::endl;
}

void Loader::UnloadBpf() {
  prog_fd_ = -1;
  DetachBpf();
  return;
}

void Loader::LoadBpf() {
  struct bpf_program* bpf_prog;

  // Load the BPF-ELF file.
  std::clog << "Loading XDP-ELF file..." << std::endl;
  int err = bpf_prog_load(bpf_filepath_.c_str(), BPF_PROG_TYPE_XDP, &bpf_obj_,
                          &prog_fd_);
  if (err) {
    std::cerr << "ERR: loading BPF-OBJ file." << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  // Find the selected prog section.
  bpf_prog = bpf_object__find_program_by_title(bpf_obj_, progsec_.c_str());
  if (!bpf_prog) {
    std::cerr << "ERR: finding prog sec: " << progsec_ << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  // Find the correspond FD.
  prog_fd_ = bpf_program__fd(bpf_prog);
  if (prog_fd_ <= 0) {
    std::cerr << "ERR: bpf_program__fd" << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  AttachBpf();
  return;
}

void Loader::DetachBpf() {
  assert(prog_fd_ == -1);
  AttachBpf();
}

void Loader::AttachBpf() {
  // Attach the FD to the interface `ifname`.
  std::clog << "Attaching to an interface..." << std::endl;
  int err = bpf_set_link_xdp_fd(ifindex_, prog_fd_, xdp_flags_);
  if (err < 0) {
    std::cerr << "ERR: link set xdp fd failed." << std::endl;
    std::cerr << "errno is: " << err << std::endl;
    return;
  }

  switch (prog_fd_) {
    case -1:
      std::clog << "Success: Bpf program detached from interface " << ifname_
                << std::endl;
      break;
    default:
      std::clog << "Success: Bpf program attached to interface " << ifname_
                << std::endl;
      break;
  }
  return;
}
