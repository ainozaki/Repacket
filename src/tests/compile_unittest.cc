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

TEST(Compile, IpFlagRes) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_flag_res = true;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_flag_res = false;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpFlagDf) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_flag_df = true;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_flag_df = false;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpFlagMf) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_flag_mf = true;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_flag_mf = false;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpOffset) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_offset = 0x00ab;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_offset = 0x00cd;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpTTL) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_ttl = 255;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_ttl = 64;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpProtocol) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_protocol = 1;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_protocol = 17;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, IpCheck) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.ip_check = 0xcafe;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.ip_check = 0xdead;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpSrc) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_src = 80;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_src = 8080;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpDest) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_dest = 8080;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_dest = 80;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpSeq) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_seq = 0xdeadcafe;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_seq = 0xcafedead;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpAckSeq) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_ack_seq = 0xabcddcba;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_ack_seq = 0xaabbccdd;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpHlen) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_hlen = 8;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_hlen = 10;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpRes) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_res = 0;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_res = 0x7;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpCWR) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_cwr = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_cwr = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpECE) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_ece = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_ece = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpURG) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_urg = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_urg = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpACK) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_ack = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_ack = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpPSH) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_psh = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_psh = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpRST) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_rst = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_rst = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpSYN) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_syn = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_syn = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpFIN) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_fin = false;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_fin = true;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpWindow) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_window = 4000;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_window = 3000;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpCheck) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_check = 0xdead;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_check = 0xabcd;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}

TEST(Compile, TcpUrgPtr) {
  struct config cfg;
  cfg.run_mode = RunMode::REWRITE;

  struct filter if_filter;
  if_filter.tcp_urg_ptr = 10;
  cfg.if_filter = if_filter;

  struct filter then_filter;
  then_filter.tcp_urg_ptr = 20;
  cfg.then_filter = then_filter;

  int err = Gen(cfg);
  EXPECT_EQ(0, err);

  err = Compile();
  EXPECT_EQ(0, err);
}
