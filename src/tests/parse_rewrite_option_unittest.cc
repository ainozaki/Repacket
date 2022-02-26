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

TEST(ParseRewriteOption, TcpSrc) {
  std::string key = "tcp_src";
  std::string value = "80";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(80, filt.tcp_src);
}

TEST(ParseRewriteOption, TcpDest) {
  std::string key = "tcp_dest";
  std::string value = "80";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(80, filt.tcp_dest);
}

// TEST(ParseRewriteOption, TcpSeq) {
//  std::string key = "tcp_seq";
//  std::string value = "0xcafecafe";
//  struct filter filt;
//  struct config cfg;
//  int err = ParseRewriteOption(key, value, filt, cfg);
//  EXPECT_EQ(0, err);
//  EXPECT_EQ(true, cfg.use_tcp);
//  EXPECT_EQ(0xcafecafe, filt.tcp_seq);
//}
//
// TEST(ParseRewriteOption, TcpAckSeq) {
//  std::string key = "tcp_ack_seq";
//  std::string value = "0xcafecafe";
//  struct filter filt;
//  struct config cfg;
//  int err = ParseRewriteOption(key, value, filt, cfg);
//  EXPECT_EQ(0, err);
//  EXPECT_EQ(true, cfg.use_tcp);
//  EXPECT_EQ(0xcafecafe, filt.tcp_ack_seq);
//}

TEST(ParseRewriteOption, TcpHlen) {
  std::string key = "tcp_hlen";
  std::string value = "5";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(5, filt.tcp_hlen);
}

TEST(ParseRewriteOption, TcpRes) {
  std::string key = "tcp_res";
  std::string value = "7";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(7, filt.tcp_res);
}

TEST(ParseRewriteOption, TcpNonce) {
  std::string key = "tcp_nonce";
  std::string value = "on";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(true, filt.tcp_nonce);
}

TEST(ParseRewriteOption, TcpCWR) {
  std::string key = "tcp_cwr";
  std::string value = "on";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(true, filt.tcp_cwr);
}

TEST(ParseRewriteOption, TcpECE) {
  std::string key = "tcp_ece";
  std::string value = "on";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(true, filt.tcp_ece);
}

TEST(ParseRewriteOption, TcpFlags) {
  std::string key = "tcp_urg";
  std::string value = "on";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(true, filt.tcp_urg);

  key = "tcp_ack";
  value = "on";
  struct filter filt2;
  struct config cfg2;
  err = ParseRewriteOption(key, value, filt2, cfg2);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg2.use_tcp);
  EXPECT_EQ(true, filt2.tcp_ack);

  key = "tcp_psh";
  value = "on";
  struct filter filt3;
  struct config cfg3;
  err = ParseRewriteOption(key, value, filt3, cfg3);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg3.use_tcp);
  EXPECT_EQ(true, filt3.tcp_psh);

  key = "tcp_rst";
  value = "off";
  struct filter filt4;
  struct config cfg4;
  err = ParseRewriteOption(key, value, filt4, cfg4);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg4.use_tcp);
  EXPECT_EQ(false, filt4.tcp_rst);

  key = "tcp_syn";
  value = "off";
  struct filter filt5;
  struct config cfg5;
  err = ParseRewriteOption(key, value, filt5, cfg5);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg5.use_tcp);
  EXPECT_EQ(false, filt5.tcp_syn);

  key = "tcp_fin";
  value = "off";
  struct filter filt6;
  struct config cfg6;
  err = ParseRewriteOption(key, value, filt6, cfg6);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg6.use_tcp);
  EXPECT_EQ(false, filt6.tcp_fin);
}

TEST(ParseRewriteOption, TcpWindow) {
  std::string key = "tcp_window";
  std::string value = "3900";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(3900, filt.tcp_window);
}

TEST(ParseRewriteOption, TcpCheck) {
  std::string key = "tcp_check";
  std::string value = "0xcafe";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(0xcafe, filt.tcp_check);
}

TEST(ParseRewriteOption, TcpUrgPtr) {
  std::string key = "tcp_urg_ptr";
  std::string value = "10";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_tcp);
  EXPECT_EQ(10, filt.tcp_urg_ptr);
}

TEST(ParseRewriteOption, UdpSrc) {
  std::string key = "udp_src";
  std::string value = "80";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_udp);
  EXPECT_EQ(80, filt.udp_src);
}

TEST(ParseRewriteOption, UdpDest) {
  std::string key = "udp_dest";
  std::string value = "80";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_udp);
  EXPECT_EQ(80, filt.udp_dest);
}

TEST(ParseRewriteOption, UdpLen) {
  std::string key = "udp_len";
  std::string value = "52";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_udp);
  EXPECT_EQ(52, filt.udp_len);
}

TEST(ParseRewriteOption, UdpCheck) {
  std::string key = "udp_check";
  std::string value = "0xcafe";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_udp);
  EXPECT_EQ(0xcafe, filt.udp_check);
}

TEST(ParseRewriteOption, IcmpType) {
  std::string key = "icmp_type";
  std::string value = "3";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_icmp);
  EXPECT_EQ(3, filt.icmp_type);
}

TEST(ParseRewriteOption, IcmpCode) {
  std::string key = "icmp_code";
  std::string value = "1";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_icmp);
  EXPECT_EQ(1, filt.icmp_code);
}

TEST(ParseRewriteOption, IcmpCheck) {
  std::string key = "icmp_check";
  std::string value = "0xcafe";
  struct filter filt;
  struct config cfg;
  int err = ParseRewriteOption(key, value, filt, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.use_icmp);
  EXPECT_EQ(0xcafe, filt.icmp_check);
}
