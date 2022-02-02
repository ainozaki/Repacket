#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "core/gen/generator.h"

TEST(Generator, FilteringUdpDest) {
  struct config cfg;
  struct filter filter;
  filter.udp_dest = 8080;
  cfg.filter = std::make_optional<struct filter>(filter);
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("udph->dest==8080", s);
}

TEST(Generator, FilteringUdpSrc) {
  struct config cfg;
  struct filter filter;
  filter.udp_src = 8080;
  cfg.filter = std::make_optional<struct filter>(filter);
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("udph->src==8080", s);
}
