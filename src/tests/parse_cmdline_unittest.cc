#include "gtest/gtest.h"

extern "C" {
#include <string.h>
}

#include "base/config.h"
#include "base/parse_cmdline.h"

TEST(ParseCmdline, Normal)
{
	int argc = 3;
	char *arg0 = "xapture";
	char *arg1 = "-i";
	char *arg2 = "eth1";
	char *argv[3] = {arg0, arg1, arg2};
	struct config cfg;
	parse_cmdline(argc, argv, cfg);
	EXPECT_EQ(RunMode::DUMPALL, cfg.run_mode);
	EXPECT_EQ(DumpMode::NORMAL, cfg.dump_mode);
}
