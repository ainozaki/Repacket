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

#include "base/define/define.h"

Loader::Loader(const Mode mode,
               uint32_t xdp_flags,
               unsigned int ifindex,
               const std::string& ifname,
               const std::string& bpf_filepath,
               const std::string& progsec)
    : mode_(mode),
      xdp_flags_(xdp_flags),
      ifindex_(ifindex),
      ifname_(ifname),
      bpf_filepath_(bpf_filepath),
      progsec_(progsec) {}

Loader::Loader(const Mode mode,
               uint32_t xdp_flags,
               unsigned int ifindex,
               const std::string& ifname)
    : mode_(mode), xdp_flags_(xdp_flags), ifindex_(ifindex), ifname_(ifname) {}

Loader::~Loader() {}

void Loader::Start() {
  switch (mode_) {
    case Mode::Attach:
      if (AttachBpf() != kSuccess) {
        std::cerr << "Failed: suspend loading program," << std::endl;
        return;
      }
      PinMaps();
      break;
    case Mode::Detach:
      DetachBpf();
      break;
    default:
      assert(false);
      break;
  }
  return;
}

int Loader::DetachBpf() {
  prog_fd_ = -1;
  int err = SetBpf();
  if (err == kSuccess) {
    std::clog << "Success: Bpf program is unloaded from interface " << ifname_
              << std::endl;
  } else {
    std::clog << "Failed: Bpf program cannot be unloaded from interface "
              << ifname_ << std::endl;
  }
  return err;
}

int Loader::AttachBpf() {
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

  err = SetBpf();
  if (err == kSuccess) {
    std::clog << "Success: Bpf program is loaded to interface " << ifname_
              << std::endl;
  } else {
    std::clog << "Failed: Bpf program cannot be loaded to interface " << ifname_
              << std::endl;
  }
  return err;
}

void Loader::PinMaps() {
  std::string pin_dir = "/sys/fs/bpf/" + ifname_;
  int err;
  if (access(pin_dir.c_str(), F_OK) != -1) {
    err = bpf_object__unpin_maps(bpf_obj_, pin_dir.c_str());
    if (err) {
      std::cerr << "ERR: Unpinning maps." << std::endl;
      return;
    }
    std::cout << "Unpinned maps!!!" << std::endl;
  }

  err = bpf_object__pin_maps(bpf_obj_, pin_dir.c_str());
  if (err) {
    std::cerr << "ERR: Pinning maps." << std::endl;
    return;
  }
  std::clog << "Success: Pinning maps at /sys/fs/bpf/" << ifname_ << std::endl;
}

int Loader::SetBpf() {
  std::clog << "Attaching to an interface..." << std::endl;
  int err = bpf_set_link_xdp_fd(ifindex_, prog_fd_, xdp_flags_);
  if (err < 0) {
    std::cerr << "ERR: set xdp fd to link failed. errno: " << err << std::endl;
    return kError;
  }
  return kSuccess;
}
