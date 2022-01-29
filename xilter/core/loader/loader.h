#ifndef LOADER_H_
#define LOADER_H_

#include <iostream>
#include <memory>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include "base/bpf_wrapper.h"
#include "base/define/define.h"
#include "base/logger.h"

class Loader {
 public:
  // Loader to attach BPF program.
  Loader(const Mode mode,
         const unsigned int xdp_flags,
         const unsigned int ifindex,
         const std::string& ifname,
         const std::string& bpf_filepath,
         const std::string& progsec,
         const bool is_dump = false);

  // Loader to detach BPF program.
  Loader(const Mode mode,
         const unsigned int xdp_flags,
         const unsigned int ifindex,
         const std::string& ifname);

  ~Loader() = default;
  Loader(const Loader&) = delete;

  // Interface function to start loading.
  void Start();

  // Public for testing.
  void DetachBpf();

 private:
  int AttachBpf();

  int SetBpf();

  void PinMaps();

  std::unique_ptr<BpfWrapper> bpf_wrapper_ = nullptr;

  Mode mode_;

  int prog_fd_;

  unsigned int xdp_flags_;

  unsigned int ifindex_;

  std::string ifname_;

  std::string bpf_filepath_;

  std::string progsec_;
};

#endif  // LOADER_H_
