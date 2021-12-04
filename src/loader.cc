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

Loader::~Loader() {}

int Loader::UnloadBpf() {
  prog_fd_ = -1;
  int err = DetachBpf();
  if (err == kSuccess) {
    std::clog << "Success: Bpf program is unloaded from interface " << ifname_
              << std::endl;
  } else {
    std::clog << "Failed: Bpf program cannot be unloaded from interface "
              << ifname_ << std::endl;
  }
  return err;
}

int Loader::LoadBpf() {
  struct bpf_program* bpf_prog;

  // Load the BPF-ELF file.
  std::clog << "Loading XDP-ELF file..." << std::endl;
  int err = bpf_prog_load(bpf_filepath_.c_str(), BPF_PROG_TYPE_XDP, &bpf_obj_,
                          &prog_fd_);
  if (err) {
    std::cerr << "ERR: cannot load BPF-OBJ file at " << bpf_filepath_
              << std::endl;
    return kError;
  }

  // Find the selected prog section.
  bpf_prog = bpf_object__find_program_by_title(bpf_obj_, progsec_.c_str());
  if (!bpf_prog) {
    std::cerr << "ERR: finding prog sec: " << progsec_ << std::endl;
    return kError;
  }

  // Find the correspond FD.
  prog_fd_ = bpf_program__fd(bpf_prog);
  if (prog_fd_ <= 0) {
    std::cerr << "ERR: bpf_program__fd" << std::endl;
    return kError;
  }

  err = AttachBpf();
  if (err == kSuccess) {
    std::clog << "Success: Bpf program is loaded to interface " << ifname_
              << std::endl;
  } else {
    std::clog << "Failed: Bpf program cannot be loaded to interface " << ifname_
              << std::endl;
  }
  return err;
}

int Loader::DetachBpf() {
  assert(prog_fd_ == -1);
  return AttachBpf();
}

int Loader::AttachBpf() {
  std::clog << "Attaching to an interface..." << std::endl;
  int err = bpf_set_link_xdp_fd(ifindex_, prog_fd_, xdp_flags_);
  if (err < 0) {
    std::cerr << "ERR: set xdp fd to link failed. errno: " << err << std::endl;
    return kError;
  }
  return kSuccess;
}
