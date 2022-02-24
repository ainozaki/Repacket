#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "base/parse_rewrite_option.h"

TEST(ParseRewriteOption, IpVer) {
  std::string key = "ip_ver";
  std::string value = "4";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(4, filt.ip_ver);
}

TEST(ParseRewriteOption, IpVerInvalid) {
  std::string key = "ip_ver";
  std::string value = "100";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseRewriteOption, IpHlen) {
  std::string key = "ip_hl";
  std::string value = "5";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(5, filt.ip_hl);
}

TEST(ParseRewriteOption, IpToS) {
  std::string key = "ip_tos";
  std::string value = "0xff";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(0xff, filt.ip_tos);
}

TEST(ParseRewriteOption, IpDSCP) {
  std::string key = "ip_dscp";
  std::string value = "0x3f";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(0x3f, filt.ip_dscp);
}

TEST(ParseRewriteOption, IpECN) {
  std::string key = "ip_ecn";
  std::string value = "0x03";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(0x03, filt.ip_ecn);
}

TEST(ParseRewriteOption, IpTotLen) {
  std::string key = "ip_tot_len";
  std::string value = "512";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(512, filt.ip_tot_len);
}

TEST(ParseRewriteOption, IpId) {
  std::string key = "ip_id";
  std::string value = "47595";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(47595, filt.ip_id);
}

TEST(ParseRewriteOption, IpTTL) {
  std::string key = "ip_ttl";
  std::string value = "64";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(64, filt.ip_ttl);
}

TEST(ParseRewriteOption, IpProtocol) {
  std::string key = "ip_protocol";
  std::string value = "17";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(17, filt.ip_protocol);
}

TEST(ParseRewriteOption, IpChecksum_InputHex) {
  std::string key = "ip_check";
  std::string value = "0xcafe";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ(0xcafe, filt.ip_check);
}

TEST(ParseRewriteOption, IpSrc) {
  std::string key = "ip_src";
  std::string value = "192.0.2.1";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_ip);
  EXPECT_EQ("192.0.2.1", filt.ip_src);
}

TEST(ParseRewriteOption, IpSrc_Invalid) {
  std::string key = "ip_src";
  std::string value = "192.0.2.300";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(1, err);
}
