#include "loader.h"

#include <cassert>
#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include "base/bpf_wrapper.h"
#include "base/define/define.h"
#include "base/logger.h"

Loader::Loader(const Mode mode,
               const unsigned int xdp_flags,
               const unsigned int ifindex,
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
               const unsigned int xdp_flags,
               const unsigned int ifindex,
               const std::string& ifname)
    : mode_(mode), xdp_flags_(xdp_flags), ifindex_(ifindex), ifname_(ifname) {}

void Loader::Start() {
  switch (mode_) {
    case Mode::Attach:
      if (AttachBpf() != kSuccess) {
        LOG_ERROR("Suspend loading program to interface %s.", ifname_.c_str());
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
  // SetBpf() unloads BPF program when fd is -1.
  prog_fd_ = -1;
  int err = SetBpf();
  if (err == kSuccess) {
    LOG_INFO("Success: Bpf program is unloaded from interface.");
  } else {
    LOG_ERROR("Failed: Cannot unload BPF program from interface %s.",
              ifname_.c_str());
  }
}

int Loader::AttachBpf() {
  // Load the BPF-ELF file.
  bpf_wrapper_ = std::make_unique<BpfWrapper>(bpf_filepath_.c_str());
  int err = bpf_wrapper_->Load();
  if (err) {
    LOG_ERROR("Failed: Cannot load BPF-OBJ file at %s.", bpf_filepath_.c_str());
    return kError;
  }

  // Find fd of the specified prog section.
  prog_fd_ = bpf_wrapper_->GetSectionFd(progsec_.c_str());
  if (prog_fd_ <= 0) {
    LOG_ERROR("Failed: Cannot get fd of section %s.", progsec_.c_str());
    return kError;
  }

  // Set fd to the interface.
  err = SetBpf();
  if (err == kSuccess) {
    LOG_INFO("Success: Bpf program is loaded to interface ");
  } else {
    LOG_ERROR("Failed: Cannot load to interface %s.", ifname_.c_str());
  }

  return err;
}

void Loader::PinMaps() {
  assert(bpf_wrapper_);

  std::string pin_dir = "/sys/fs/bpf/" + ifname_;
  int err;
  // Unpin maps in advance.
  if (access(pin_dir.c_str(), F_OK) != -1) {
    err = bpf_wrapper_->UnpinMaps(pin_dir);
    if (err) {
      LOG_ERROR("Failed: Cannot unpinning maps to %s.", pin_dir);
      return;
    }
    LOG_INFO("Success: Unpinned maps!!!");
  }

  // Pin maps.
  err = bpf_wrapper_->PinMaps(pin_dir);
  if (err) {
    LOG_ERROR("Failed: Cannot pinning maps at %s.", pin_dir);
    return;
  }
  LOG_INFO("Success: Pinning maps at %s.", pin_dir);
}

int Loader::SetBpf() {
  // set |prog_fd_| to the interface.
  int err = BpfWrapper::SetFdToInterface(ifindex_, prog_fd_, xdp_flags_);
  if (err < 0) {
    LOG_ERROR("Failed: Cannot set xdp fd to %s.", ifname_);
    return kError;
  }
  return kSuccess;
}
