#include "moctok_filter.h"

#include <memory>

#include "common/define.h"
#include "loader.h"

MoctokFilter::MoctokFilter(const struct config& cfg) : config_(cfg) {
  loader_ = std::make_unique<Loader>(cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                                     cfg.bpf_filepath, cfg.progsec);
  LoadBpf();
};

MoctokFilter::~MoctokFilter() {
  std::cout << "MoctokFilter destruction" << std::endl;
}

void MoctokFilter::LoadBpf() {
  if (config_.unload) {
    loader_->UnloadBpf();
    return;
  }
  loader_->LoadBpf();
  bpf_obj_ = loader_->bpf_obj();
  return;
}
