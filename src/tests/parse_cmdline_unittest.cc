#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "base/parse_cmdline.h"

TEST(ParseCmdline, RunModeAttach) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-a"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(RunMode::ATTACH, cfg.run_mode);
}

TEST(ParseCmdline, RunModeDetach) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-d"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(RunMode::DETACH, cfg.run_mode);
}

TEST(ParseCmdline, RunModeRewrite) {
  const std::string argv[] = {"repakcet", "-i", "veth1"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(RunMode::REWRITE, cfg.run_mode);
}

TEST(ParseCmdline, TooLessOption) {
  const std::string argv[] = {"repakcet"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseCmdline, TooMuchOption) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-a", "-d"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseCmdline, InvalidInterface) {
  const std::string argv[] = {"repakcet", "-i", "veth100", "-a"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseCmdline, InvalidOption) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-p"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseCmdline, ReflectRewriteOption) {
  const std::string argv[] = {"repakcet", "-i",   "veth1",  "if",
                              "all",      "then", "ip_ver", "4"};
  struct config cfg;
  int err = ParseCmdline(sizeof(argv) / sizeof(argv[0]), argv, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(true, cfg.then_filter.ip_ver.has_value());
  EXPECT_EQ(false, cfg.if_filter.ip_ver.has_value());
}
