#ifndef LOADER_H_
#define LOADER_H_

#include <iostream>
#include <string>

#include <stdio.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf.h>
#include <libbpf.h>

#include "common/define.h"

class Loader {
 public:
  Loader() = default;
  ~Loader() = default;
  Loader(const Loader&) = delete;

  // Load BPF-ELF file and attach it to an interface.
  struct bpf_object* LoadAndAttach(const struct config& cfg);

  // Detach BPF.
  void Detach(int ifindex, __u32 xdp_flags);
};

#endif  // LOADER_H_
