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

TEST(Compile, IpHlen) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_hl = 5;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_hl = 6;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpTos) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_tos = 0;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_tos = 255;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpDSCP) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_dscp = 0;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_dscp = 0xf0;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpECN) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_ecn = 0;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_ecn = 0x03;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpTotLen) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_tot_len = 52;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_tot_len = 84;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpID) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_id = 0xcafe;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_id = 0xfeca;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}
