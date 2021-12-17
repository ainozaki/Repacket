#ifndef LOADER_H_
#define LOADER_H_

#include <iostream>
#include <memory>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <libbpf.h>

#include "base/define/define.h"

class Controller;

class Loader {
 public:
  // Loader to attach BPF program.
  Loader(const Mode mode,
         uint32_t xdp_flags,
         unsigned int ifindex,
         const std::string& ifname,
         const std::string& bpf_filepath,
         const std::string& progsec);

  // Loader to detach BPF program.
  Loader(const Mode mode,
         uint32_t xdp_flags,
         unsigned int ifindex,
         const std::string& ifname);

  ~Loader();
  Loader(const Loader&) = delete;

  // Public for testing.
  int DetachBpf();

 private:
  void Load(const Mode mode);

  int AttachBpf();

  int SetBpf();

  void PinMaps();

  Controller* controller_;

  struct bpf_object* bpf_obj_;

  int prog_fd_;

  uint32_t xdp_flags_;

  unsigned int ifindex_;

  std::string ifname_;

  std::string bpf_filepath_;

  std::string progsec_;
};

#endif  // LOADER_H_
