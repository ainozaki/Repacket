#include "moctok.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <string>

#include <bpf.h>

#include "base/define/define.h"
#include "core/generator/generator.h"
#include "core/loader/moctok_filter.h"
#include "core/logger/map.h"

MocTok::MocTok(struct config& cfg) : config_(cfg) {
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
      map_ = std::make_unique<Map>(config_.ifname);
      map_->Stats();
      break;
    default:
      assert(false);
      break;
  }
}
