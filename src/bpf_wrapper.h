#ifndef BPF_WRAPPER_H_
#define BPF_WRAPPER_H_

#include <string>

#include <bpf.h>

class BpfWrapper {
 public:
  BpfWrapper() = default;
  ~BpfWrapper() = default;
  BpfWrapper(const BpfWrapper&) = delete;

  // Helper function to get bpf_map_info from specified |fd|.
  // Returns 0 in success.
  static int BpfGetMapInfoByFd(int fd, struct bpf_map_info* info);

  // Helper funciton to get fd of the bpf object in |path|.
  // Returns fd.
  static int BpfGetPinnedObjFd(const std::string& path);

  // Helper function to get map value from user space.
  // Returns 0 in success.
  static int BpfMapLookupElem(int map_fd, void* key, void* value);
};
#endif  // BPF_WRAPPER_H_
