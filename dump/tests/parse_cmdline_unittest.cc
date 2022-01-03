#include "gtest/gtest.h"

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
	EXPECT_EQ(true, cfg.is_detach);
}
