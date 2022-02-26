#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "core/gen/gen_dynamic.h"

TEST(GenDynamic, FilteringUdpDest) {
  struct config cfg;
  struct filter filter;
  filter.udp_dest = 49365;
  cfg.if_filter = filter;
  cfg.use_udp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("if(udph&&udph->dest==bpf_htons(49365))", s);
}

TEST(GenDynamic, FilteringUdpSrc) {
  struct config cfg;
  struct filter filter;
  filter.udp_src = 49365;
  cfg.if_filter = filter;
  cfg.use_udp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("if(udph&&udph->source==bpf_htons(49365))", s);
}

TEST(GenDynamic, FilteringUdpLen) {
  struct config cfg;
  struct filter filter;
  filter.udp_len = 40;
  cfg.if_filter = filter;
  cfg.use_udp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("if(udph&&udph->len==bpf_htons(40))", s);
}

TEST(GenDynamic, FilteringUdpCheck) {
  struct config cfg;
  struct filter filter;
  filter.udp_check = 10000;
  cfg.if_filter = filter;
  cfg.use_udp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("if(udph&&udph->check==bpf_htons(10000))", s);
}

TEST(GenDynamic, FilteringIcmpType) {
  struct config cfg;
  struct filter filter;
  filter.icmp_type = 3;
  cfg.if_filter = filter;
  cfg.use_icmp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("if(icmph&&icmph->type==bpf_htons(3))", s);
}

TEST(GenDynamic, FilteringIcmpCode) {
  struct config cfg;
  struct filter filter;
  filter.icmp_code = 1;
  cfg.if_filter = filter;
  cfg.use_icmp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("if(icmph&&icmph->code==bpf_htons(1))", s);
}

TEST(GenDynamic, FilteringIcmpCheck) {
  struct config cfg;
  struct filter filter;
  filter.icmp_check = 10000;
  cfg.if_filter = filter;
  cfg.use_icmp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ("if(icmph&&icmph->checksum==bpf_htons(10000))", s);
}

TEST(GenDynamic, FilteringTwoElements) {
  struct config cfg;
  struct filter filter;
  filter.udp_src = 49365;
  filter.udp_dest = 49356;
  cfg.if_filter = filter;
  cfg.use_udp = true;
  std::string s = FilteringStatement(cfg);
  EXPECT_EQ(
      "if(udph&&udph->source==bpf_htons(49365)&&udph->dest==bpf_htons(49356))",
      s);
}
