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

#include "base/bpf_wrapper.h"
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

void Loader::DetachBpf() {
  prog_fd_ = -1;

  // SetBpf() unloads BPF program when |prog_fd_| is -1.
  int err = SetBpf();
  if (err == kSuccess) {
    std::clog << "Success: Bpf program is unloaded from interface " << ifname_
              << std::endl;
  } else {
    std::cerr << "Failed: Bpf program cannot be unloaded from interface "
              << ifname_ << std::endl;
  }
}

int Loader::AttachBpf() {
  // Load the BPF-ELF file.
  int err = bpf_prog_load(bpf_filepath_.c_str(), BPF_PROG_TYPE_XDP, &bpf_obj_,
                          &prog_fd_);
  if (err) {
    std::cerr << "ERR: cannot load BPF-OBJ file at " << bpf_filepath_
              << std::endl;
    return kError;
  }

  // Find fd of the specified prog section.
  prog_fd_ = bpf::GetSectionFd(bpf_obj_, progsec_);
  if (prog_fd_ <= 0) {
    std::cerr << "ERR: bpf_program__fd" << std::endl;
    return kError;
  }

  // Set fd to interface.
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
  // Unpin maps in advance.
  if (access(pin_dir.c_str(), F_OK) != -1) {
    err = bpf_object__unpin_maps(bpf_obj_, pin_dir.c_str());
    if (err) {
      std::cerr << "ERR: Unpinning maps." << std::endl;
      return;
    }
    std::cout << "Unpinned maps!!!" << std::endl;
  }

  // Pin maps.
  err = bpf_object__pin_maps(bpf_obj_, pin_dir.c_str());
  if (err) {
    std::cerr << "ERR: Pinning maps at " << pin_dir << std::endl;
    return;
  }
  std::clog << "Success: Pinning maps at " << pin_dir << std::endl;
}

int Loader::SetBpf() {
  // set |prog_fd_| to the interface,
  int err = bpf_set_link_xdp_fd(ifindex_, prog_fd_, xdp_flags_);
  if (err < 0) {
    std::cerr << "ERR: Set xdp fd to " << ifname_ << " failed." << std::endl;
    return kError;
  }
  return kSuccess;
}
