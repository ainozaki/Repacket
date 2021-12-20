#include "bpf_wrapper.h"

#include <iostream>
#include <string>

#include <bpf/bpf.h>
#include <libbpf.h>

#include "base/define/define.h"

namespace bpf {

int GetMapInfoByFd(int fd, struct bpf_map_info* info) {
  __u32 info_len = sizeof(*info);
  // returns err
  return bpf_obj_get_info_by_fd(fd, info, &info_len);
}

int GetPinnedObjFd(const std::string& path) {
  return bpf_obj_get(path.c_str());
}

int MapLookupElem(int map_fd, void* key, void* value) {
  return bpf_map_lookup_elem(map_fd, key, value);
}

int GetSectionFd(struct bpf_object* bpf_obj, const std::string& progsec) {
  struct bpf_program* bpf_prog;

  // Find the selected prog section.
  bpf_prog = bpf_object__find_program_by_title(bpf_obj, progsec.c_str());
  if (!bpf_prog) {
    std::cerr << "ERR: finding prog sec: " << progsec << std::endl;
    return kError;
  }

  // Find the correspond FD.
  int prog_fd = bpf_program__fd(bpf_prog);
  if (prog_fd <= 0) {
    std::cerr << "ERR: bpf_program__fd" << std::endl;
    return kError;
  }
  return prog_fd;
}

}  // namespace bpf
