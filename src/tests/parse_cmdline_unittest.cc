#include "gtest/gtest.h"

#include <string>

#include "base/config.h"
#include "base/parse_cmdline.h"

TEST(ParseCmdline, RunModeDumpAll)
{
	int argc = 3;
	const std::string argv[] = {"xapture", "-i", "eth1"};
	struct config cfg;
	int err = ParseCmdline(argc, argv, cfg);
	EXPECT_EQ(0, err);
	EXPECT_EQ(RunMode::DUMPALL, cfg.run_mode);
	EXPECT_EQ(DumpMode::NORMAL, cfg.dump_mode);
}

TEST(ParseCmdline, RunModeAttach)
{
	int argc = 4;
	const std::string argv[] = {"xapture", "-i", "eth1", "-a"};
	struct config cfg;
	int err = ParseCmdline(argc, argv, cfg);
	EXPECT_EQ(0, err);
	EXPECT_EQ(RunMode::ATTACH, cfg.run_mode);
}

TEST(ParseCmdline, RunModeDetach)
{
	int argc = 4;
	const std::string argv[] = {"xapture", "-i", "eth1", "-z"};
	struct config cfg;
	int err = ParseCmdline(argc, argv, cfg);
	EXPECT_EQ(0, err);
	EXPECT_EQ(RunMode::DETACH, cfg.run_mode);
}

TEST(ParseCmdline, RunModeRewrite)
{
	int argc = 4;
	const std::string argv[] = {"xapture", "-i", "eth1", "-r"};
	struct config cfg;
	int err = ParseCmdline(argc, argv, cfg);
	EXPECT_EQ(0, err);
	EXPECT_EQ(RunMode::REWRITE, cfg.run_mode);
}

TEST(ParseCmdline, RunModeDrop)
{
	int argc = 4;
	const std::string argv[] = {"xapture", "-i", "eth1", "-d"};
	struct config cfg;
	int err = ParseCmdline(argc, argv, cfg);
	EXPECT_EQ(0, err);
	EXPECT_EQ(RunMode::DROP, cfg.run_mode);
}

TEST(ParseCmdline, DumpModeFriendly)
{
	int argc = 4;
	const std::string argv[] = {"xapture", "-i", "eth1", "-f"};
	struct config cfg;
	int err = ParseCmdline(argc, argv, cfg);
	EXPECT_EQ(0, err);
	EXPECT_EQ(DumpMode::FRIENDLY, cfg.dump_mode);
}

TEST(ParseCmdline, RequiredOption)
{
	int argc = 1;
	const std::string argv[] = {"xapture"};
	struct config cfg;
	int err = ParseCmdline(argc, argv, cfg);
	EXPECT_EQ(1, err);
}
