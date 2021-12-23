#ifndef BPF_WRAPPER_H_
#define BPF_WRAPPER_H_

#include <string>

#include <bpf/bpf.h>
#include <libbpf.h>

class BpfWrapper {
 public:
  BpfWrapper(const std::string& bpf_filepath);
  ~BpfWrapper() = default;
  BpfWrapper(const BpfWrapper&) = delete;

  // Load BPF object file and get fd.
  // Returns 0 in success.
  int Load();

  // Helper function to get fd of |progsec| in |bpf_obj_|.
  // Make sure to call after Load().
  // Returns fd in success, |kError| in fail.
  int GetSectionFd(const std::string& progsec);

  // Pinning map in |bpf_obj_| to |pin_dir_|.
  // Returns err.
  int PinMaps(const std::string& pin_dir);

  // Unpinning map in |bpf_obj_| from |pin_dir_|.
  // Returns err.
  int UnpinMaps(const std::string& pin_dir);

  // Set fd to the interface specified by |ifindex|.
  // Returns err.
  static int SetFdToInterface(const int ifindex,
                              const int fd,
                              const unsigned int xdp_flags);

  /* Map */
  // Helper function to get bpf_map_info from specified |fd|.
  // Returns 0 in success.
  static int GetMapInfoByFd(int fd, struct bpf_map_info* info);

  // Helper funciton to get fd of the bpf object in |path|.
  // Returns fd.
  static int GetPinnedObjFd(const std::string& path);

  // Helper function to get map value from user space.
  // Returns 0 in success.
  static int MapLookupElem(int map_fd, void* key, void* value);

 private:
  struct bpf_object* bpf_obj_;

  std::string bpf_filepath_;

  int prog_fd_;
};

#endif  // BPF_WRAPPER_H_
