#include "loader.h"

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
  std::cout << "Loader destruction" << std::endl;
}

void Loader::UnloadBpf() {
  prog_fd_ = -1;
  AttachBpf();
  return;
}

void Loader::LoadBpf() {
  struct bpf_program* bpf_prog;

  // Load the BPF-ELF file.
  std::cout << "Loading XDP-ELF file..." << std::endl;
  int err = bpf_prog_load(bpf_filepath_.c_str(), BPF_PROG_TYPE_XDP, &bpf_obj_,
                          &prog_fd_);
  if (err) {
    std::cout << "ERR: loading BPF-OBJ file." << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  // Find the selected prog section.
  bpf_prog = bpf_object__find_program_by_title(bpf_obj_, progsec_.c_str());
  if (!bpf_prog) {
    std::cout << "ERR: finding prog sec: " << progsec_ << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  // Find the correspond FD.
  prog_fd_ = bpf_program__fd(bpf_prog);
  if (prog_fd_ <= 0) {
    std::cout << "ERR: bpf_program__fd" << std::endl;
    exit(EXIT_FAIL_BPF);
  }

  AttachBpf();
  return;
}

void Loader::AttachBpf() {
  // Attach the FD to the interface `ifname`.
  std::cout << "Attaching to an interface..." << std::endl;
  int err = bpf_set_link_xdp_fd(ifindex_, prog_fd_, xdp_flags_);
  if (err < 0) {
    std::cout << "ERR: link set xdp fd failed." << std::endl;
    std::cout << "errno is: " << err << std::endl;
    return;
  }

  std::cout << "Success: Change has applied to " << ifname_ << std::endl;
  return;
}
