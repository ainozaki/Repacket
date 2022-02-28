#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "core/gen/gen_controller.h"

TEST(Compile, IpVer) {
  struct config cfg;
	cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
	if_filter.ip_ver = 4;
	cfg.if_filter = if_filter;
  
  struct filter then_filter;
	then_filter.ip_ver = 6;
	cfg.then_filter = then_filter;

	int err = Gen(cfg);
  EXPECT_EQ(0, err);

	err = Compile();
  EXPECT_EQ(0, err);
}
