#include <gtest/gtest.h>

#include <vector>

#include "common/define.h"
#include "generator.h"
#include "yaml_handler.h"

TEST(GeneratorTest, ReadYaml) {
  std::vector<Policy> policy = YamlHandler::ReadYaml("data/test.yaml");
  EXPECT_EQ(2, policy.size());
  // second policy.
  EXPECT_EQ(Action::Drop, policy[0].action);
  EXPECT_EQ("tcp", policy[0].ip_protocol);
  EXPECT_EQ("192.168.33.10", policy[0].ip_saddr);
  EXPECT_EQ("192.168.44.10", policy[0].ip_daddr);
  EXPECT_EQ(0, policy[0].ip_ttl_min);
  EXPECT_EQ(64, policy[0].ip_ttl_max);
  EXPECT_EQ(32, policy[0].ip_tot_len_min);
  EXPECT_EQ(1024, policy[0].ip_tot_len_max);

  // first policy.
  EXPECT_EQ(Action::Pass, policy[1].action);
  EXPECT_EQ("udp", policy[1].ip_protocol);
  EXPECT_EQ("", policy[1].ip_saddr);
  EXPECT_EQ("", policy[1].ip_daddr);
  EXPECT_EQ(-1, policy[1].ip_ttl_min);
  EXPECT_EQ(-1, policy[1].ip_ttl_max);
  EXPECT_EQ(-1, policy[1].ip_tot_len_min);
  EXPECT_EQ(-1, policy[1].ip_tot_len_max);
}
