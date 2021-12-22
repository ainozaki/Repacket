#ifndef MOCTOK_H_
#define MOCTOK_H_

#include <memory>

#include "base/define/define.h"
#include "core/generator/generator.h"
#include "core/loader/loader.h"
#include "core/stats/stats.h"

class Loader;

class MocTok {
 public:
  MocTok(struct config& cfg);
  ~MocTok() = default;
  MocTok(const MocTok&) = delete;

 private:
  std::unique_ptr<Loader> loader_;

  std::unique_ptr<Generator> generator_;

  std::unique_ptr<Stats> stats_;

  struct config config_;
};

#endif  // MOCTOK_H_
