#include <gtest/gtest.h>

#include <vector>

#include "common/define.h"
#include "yaml_handler.h"

TEST(YamlHandlerTest, ReadYaml) {
  std::vector<Filter> filter = YamlHandler::ReadYaml("data/test.yaml");
  EXPECT_EQ(2, filter.size());
  // second filter.
  EXPECT_EQ(Action::Drop, filter[0].action);
  EXPECT_EQ("tcp", filter[0].ip_protocol);
  EXPECT_EQ("192.168.33.10", filter[0].ip_saddr);
  EXPECT_EQ("192.168.44.10", filter[0].ip_daddr);
  EXPECT_EQ(0, filter[0].ip_ttl_min);
  EXPECT_EQ(64, filter[0].ip_ttl_max);
  EXPECT_EQ(32, filter[0].ip_tot_len_min);
  EXPECT_EQ(1024, filter[0].ip_tot_len_max);
  EXPECT_EQ("0x03", filter[0].ip_tos);
  EXPECT_EQ(3, filter[0].icmp_type);
  EXPECT_EQ(1, filter[0].icmp_code);
  EXPECT_EQ(22, filter[0].tcp_src);
  EXPECT_EQ(22, filter[0].tcp_dst);
  EXPECT_EQ(true, filter[0].tcp_urg);
  EXPECT_EQ(true, filter[0].tcp_ack);
  EXPECT_EQ(true, filter[0].tcp_psh);
  EXPECT_EQ(true, filter[0].tcp_rst);
  EXPECT_EQ(true, filter[0].tcp_syn);
  EXPECT_EQ(true, filter[0].tcp_fin);

  // first filter.
  EXPECT_EQ(Action::Pass, filter[1].action);
  EXPECT_EQ("udp", filter[1].ip_protocol);
  EXPECT_EQ("", filter[1].ip_saddr);
  EXPECT_EQ("", filter[1].ip_daddr);
  EXPECT_EQ(-1, filter[1].ip_ttl_min);
  EXPECT_EQ(-1, filter[1].ip_ttl_max);
  EXPECT_EQ(-1, filter[1].ip_tot_len_min);
  EXPECT_EQ(-1, filter[1].ip_tot_len_max);
  EXPECT_EQ("", filter[1].ip_tos);
  EXPECT_EQ(-1, filter[1].icmp_type);
  EXPECT_EQ(-1, filter[1].icmp_code);
  EXPECT_EQ(-1, filter[1].tcp_src);
  EXPECT_EQ(-1, filter[1].tcp_dst);
  EXPECT_EQ(false, filter[1].tcp_urg);
  EXPECT_EQ(false, filter[1].tcp_ack);
  EXPECT_EQ(false, filter[1].tcp_psh);
  EXPECT_EQ(false, filter[1].tcp_rst);
  EXPECT_EQ(false, filter[1].tcp_syn);
  EXPECT_EQ(false, filter[1].tcp_fin);
}
