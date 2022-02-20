#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "base/parse_cmdline.h"

TEST(ParseCmdline, RunModeAttach) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-a"};
  struct config cfg;
  int err = ParseCmdline(/*argc=*/4, argv, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(RunMode::ATTACH, cfg.run_mode);
}

TEST(ParseCmdline, RunModeDetach) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-d"};
  struct config cfg;
  int err = ParseCmdline(/*argc=*/4, argv, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(RunMode::DETACH, cfg.run_mode);
}

TEST(ParseCmdline, RunModeRewrite) {
  const std::string argv[] = {"repakcet", "-i", "veth1"};
  struct config cfg;
  int err = ParseCmdline(/*argc=*/3, argv, cfg);
  EXPECT_EQ(0, err);
  EXPECT_EQ(RunMode::REWRITE, cfg.run_mode);
}

TEST(ParseCmdline, TooLessOption) {
  const std::string argv[] = {"repakcet"};
  struct config cfg;
  int err = ParseCmdline(/*argc=*/1, argv, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseCmdline, TooMuchOption) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-a", "-d"};
  struct config cfg;
  int err = ParseCmdline(/*argc=*/1, argv, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseCmdline, InvalidInterface) {
  const std::string argv[] = {"repakcet", "-i", "veth100", "-a"};
  struct config cfg;
  int err = ParseCmdline(/*argc=*/1, argv, cfg);
  EXPECT_EQ(1, err);
}

TEST(ParseCmdline, InvalidOption) {
  const std::string argv[] = {"repakcet", "-i", "veth1", "-p"};
  struct config cfg;
  int err = ParseCmdline(/*argc=*/1, argv, cfg);
  EXPECT_EQ(1, err);
}
