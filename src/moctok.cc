#include "moctok.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <string>

#include <bpf.h>

#include "base/define/define.h"
#include "core/generator/generator.h"
#include "core/loader/moctok_filter.h"
#include "core/stats/stats.h"

MocTok::MocTok(struct config& cfg) : config_(cfg) {
  int err;
  switch (config_.mode) {
    case Mode::Generate:
      // Generate XDP program according to rules in yaml file.
      generator_ = std::make_unique<Generator>(config_.yaml_filepath);
      break;
      // TODO: rename Load/Unload to Attach/Detach
    case Mode::Load:
      // MocktokFilter loads Bpf program.
      // TODO: separate loading role from constructor.
      filter_ = std::make_unique<MoctokFilter>(cfg);
      break;
    case Mode::Unload:
      // MocktokFilter unloads Bpf program.
      filter_ = std::make_unique<MoctokFilter>(cfg);
      break;
    case Mode::Stats:
      // Get statics on |config_.ifname|.
      stats_ = std::make_unique<Stats>(config_.ifname);
      err = stats_->Start();
      if (err) {
        std::cerr << "Error detected. Finish getting stats." << std::endl;
      }
      break;
    default:
      assert(false);
      break;
  }
}
