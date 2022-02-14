#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "core/gen/generator.h"

TEST(Generator, FilteringUdpDest) {
  struct config cfg;
  struct filter filter;
  filter.udp_dest = 49365;
  cfg.if_filter = filter;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("udph&&udph->dest==bpf_htons(49365)", s);
}

TEST(Generator, FilteringUdpSrc) {
  struct config cfg;
  struct filter filter;
  filter.udp_src = 49365;
  cfg.if_filter = filter;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("udph&&udph->source==bpf_htons(49365)", s);
}

TEST(Generator, FilteringTwoElements) {
  struct config cfg;
  struct filter filter;
  filter.udp_src = 49365;
  filter.udp_dest = 49356;
  cfg.if_filter = filter;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ(
      "udph&&udph->source==bpf_htons(49365)&&udph->dest==bpf_htons(49356)", s);
}
