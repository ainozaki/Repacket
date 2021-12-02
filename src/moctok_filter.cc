#include "moctok_filter.h"

#include <cassert>
#include <memory>

#include "common/define.h"
#include "loader.h"

MoctokFilter::MoctokFilter(const struct config& cfg) : config_(cfg) {
  loader_ = std::make_unique<Loader>(cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                                     cfg.bpf_filepath, cfg.progsec);
  Load();
};

MoctokFilter::~MoctokFilter() {
  std::clog << "MoctokFilter destruction" << std::endl;
}

void MoctokFilter::Load() {
  switch (config_.mode) {
    case Mode::Unload:
      loader_->UnloadBpf();
      break;
    case Mode::Load:
      loader_->LoadBpf();
      bpf_obj_ = loader_->bpf_obj();
      break;
    default:
      assert(false);
      break;
  }
  return;
}
