#include "moctok.h"

#include <cassert>
#include <memory>

#include "base/define/define.h"
#include "core/generator/generator.h"
#include "core/loader/loader.h"
#include "core/stats/stats.h"

MocTok::MocTok(struct config& cfg) : config_(cfg) {
  switch (config_.mode) {
    case Mode::Generate:
      // Generate XDP program according to rules in yaml file.
      generator_ = std::make_unique<Generator>(config_.yaml_filepath,
                                               config_.output_filepath);
      generator_->Start();
      break;
    case Mode::Attach:
      // Attach Bpf program.
      loader_ = std::make_unique<Loader>(config_.mode, config_.xdp_flags,
                                         config_.ifindex, config_.ifname,
                                         config_.bpf_filepath, config_.progsec);
      loader_->Start();
      break;
    case Mode::Detach:
      // Detach Bpf program.
      loader_ = std::make_unique<Loader>(config_.mode, config_.xdp_flags,
                                         config_.ifindex, config_.ifname);
      loader_->Start();
      break;
    case Mode::Stats:
      // Get statics on |config_.ifname|.
      stats_ = std::make_unique<Stats>(config_.ifname, config_.yaml_filepath);
      stats_->Start();
      break;
    default:
      assert(false);
      break;
  }
}
