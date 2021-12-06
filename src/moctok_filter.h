#ifndef MOCTOK_FILTER_H_
#define MOCTOK_FILTER_H_

#include <memory>

#include <bpf/bpf.h>

#include "common/define.h"
#include "loader.h"

class MoctokFilter {
 public:
  MoctokFilter(const struct config& cfg);
  ~MoctokFilter();
  MoctokFilter(const MoctokFilter&) = delete;

  void Load();

  // Make sure to call this function after Load().
  struct bpf_object* bpf_obj() {
    return bpf_obj_;
  }

 private:
  void PinMaps();

  struct bpf_object* bpf_obj_;

  struct config config_;

  std::unique_ptr<Loader> loader_;
};

#endif  // MOCTOK_FILTER_H_
