#ifndef LOADER_H_
#define LOADER_H_

#include <iostream>
#include <memory>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf.h>
#include <libbpf.h>

#include "common/define.h"

class Controller;

class Loader {
 public:
  Loader(uint32_t xdp_flags,
         unsigned int ifindex,
         const std::string& ifname,
         const std::string& bpf_filepath,
         const std::string& progsec);
  ~Loader();
  Loader(const Loader&) = delete;

  // Load BPF-ELF file and attach it to an interface.
  struct bpf_object* LoadAndAttach();

  // Detach BPF.
  void Detach(int ifindex, __u32 xdp_flags);

 private:
  void SignalHandler(int signum);

  Controller* controller_;

  uint32_t xdp_flags_;

  unsigned int ifindex_;

  std::string ifname_;

  std::string bpf_filepath_;

  std::string progsec_;
};

#endif  // LOADER_H_
