#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "base/parse_rewrite_option.h"

TEST(ParseRewriteOption, RunModeAttach) {
  std::string key = "ip_ver";
  std::string value = "4";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, &filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(4, filt.ip_ver);
}
