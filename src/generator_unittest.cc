#include <gtest/gtest.h>

#include <vector>

#include "common/define.h"
#include "generator.h"
#include "yaml_handler.h"

TEST(GeneratorTest, ReadYaml) {
  std::vector<Policy> policy = YamlHandler::ReadYaml("data/test.yaml");
  EXPECT_EQ(2, policy.size());
  // first policy.
  EXPECT_EQ(Action::Pass, policy[0].action);
  EXPECT_EQ("udp", policy[0].ip_protocol);

  // second policy.
  EXPECT_EQ(Action::Drop, policy[1].action);
  EXPECT_EQ("tcp", policy[1].ip_protocol);
  EXPECT_EQ("192.168.33.10", policy[1].ip_saddr);
  EXPECT_EQ("192.168.44.10", policy[1].ip_daddr);
}
