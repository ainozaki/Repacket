#include <gtest/gtest.h>

#include <vector>

#include "common/define.h"
#include "generator.h"

TEST(GeneratorTest, ReadYaml) {
  Generator generator("data/test.yaml");
  generator.StartReadYaml();
  std::vector<Policy> access_policies = generator.access_policies();
  std::vector<Policy> deny_policies = generator.deny_policies();
  EXPECT_EQ(2, access_policies.size());
  EXPECT_EQ(1, deny_policies.size());
  // first access policy.
  EXPECT_EQ(1, access_policies[0].priority);
  EXPECT_EQ(-1, access_policies[0].port);
  EXPECT_EQ("192.168.33.1", access_policies[0].ip_address);
  EXPECT_EQ("icmp", access_policies[0].protocol);

  // second access polixy.
  EXPECT_EQ(2, access_policies[1].priority);
  EXPECT_EQ(65535, access_policies[1].port);
  EXPECT_EQ("", access_policies[1].ip_address);
  EXPECT_EQ("", access_policies[1].protocol);

  // first deny polixy.
  EXPECT_EQ(0, deny_policies[0].priority);
  EXPECT_EQ(-1, deny_policies[0].port);
  EXPECT_EQ("10.2.20.1", deny_policies[0].ip_address);
  EXPECT_EQ("", deny_policies[0].protocol);
}
