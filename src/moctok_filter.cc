#include "moctok_filter.h"

#include <cassert>
#include <memory>

#include <unistd.h>

#include "common/define.h"
#include "loader.h"

MoctokFilter::MoctokFilter(const struct config& cfg) : config_(cfg) {
  loader_ = std::make_unique<Loader>(cfg.xdp_flags, cfg.ifindex, cfg.ifname,
                                     cfg.bpf_filepath, cfg.progsec);
  Load();
};

MoctokFilter::~MoctokFilter() {}

void MoctokFilter::Load() {
  switch (config_.mode) {
    case Mode::Unload:
      loader_->UnloadBpf();
      break;
    case Mode::Load:
      if (loader_->LoadBpf() != kSuccess) {
        std::cerr << "Failed: suspend loading program," << std::endl;
        return;
      }
      bpf_obj_ = loader_->bpf_obj();
      PinMaps();
      break;
    default:
      assert(false);
      break;
  }
  return;
}

void MoctokFilter::PinMaps() {
  std::string pin_dir = "/sys/fs/bpf/" + config_.ifname;
  int err;
  if (access(pin_dir.c_str(), F_OK) != -1) {
    err = bpf_object__unpin_maps(bpf_obj_, pin_dir.c_str());
    if (err) {
      std::cerr << "ERR: Unpinning maps." << std::endl;
      return;
    }
  }

  err = bpf_object__pin_maps(bpf_obj_, pin_dir.c_str());
  if (err) {
    std::cerr << "ERR: Pinning maps." << std::endl;
    return;
  }
}
