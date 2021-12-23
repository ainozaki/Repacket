#include "bpf_wrapper.h"

#include <iostream>
#include <string>

#include <bpf/bpf.h>
#include <libbpf.h>

#include "base/define/define.h"

BpfWrapper::BpfWrapper(const std::string& bpf_filepath)
    : bpf_filepath_(bpf_filepath){};

int BpfWrapper::Load() {
  int err = bpf_prog_load(bpf_filepath_.c_str(), BPF_PROG_TYPE_XDP, &bpf_obj_,
                          &prog_fd_);
  return err;
}

int BpfWrapper::GetSectionFd(const std::string& progsec) {
  struct bpf_program* bpf_prog;

  // Find the selected prog section.
  bpf_prog = bpf_object__find_program_by_title(bpf_obj_, progsec.c_str());
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

int BpfWrapper::PinMaps(const std::string& pin_dir) {
  int err = bpf_object__pin_maps(bpf_obj_, pin_dir.c_str());
  return err;
}

int BpfWrapper::UnpinMaps(const std::string& pin_dir) {
  int err = bpf_object__unpin_maps(bpf_obj_, pin_dir.c_str());
  return err;
}

// static
int BpfWrapper::SetFdToInterface(const int ifindex,
                                 const int fd,
                                 const unsigned int xdp_flags) {
  int err = bpf_set_link_xdp_fd(ifindex, fd, xdp_flags);
  return err;
}

// static
int BpfWrapper::GetMapInfoByFd(int fd, struct bpf_map_info* info) {
  __u32 info_len = sizeof(*info);
  // returns err
  return bpf_obj_get_info_by_fd(fd, info, &info_len);
}

// static
int BpfWrapper::GetPinnedObjFd(const std::string& path) {
  return bpf_obj_get(path.c_str());
}

// static
int BpfWrapper::MapLookupElem(int map_fd, void* key, void* value) {
  return bpf_map_lookup_elem(map_fd, key, value);
}
