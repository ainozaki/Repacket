#include "gtest/gtest.h"

#include <string>

extern "C"
{
#include "define.h"
#include "parse_cmdline.h"
}

TEST(ParseCmdline, Normal)
{
	int argc = 2;
	char *arg0 = "./parse_cmdline";
	char *arg1 = "-d";
	char *argv[] = {arg0, arg1};
	struct config cfg;
	parse_cmdline(argc, argv, &cfg);
	enum mode mode_detach = DETACH;
	EXPECT_EQ(mode_detach, cfg.run_mode);
}
