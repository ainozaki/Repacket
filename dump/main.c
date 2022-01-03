#include <linux/if_link.h>

#include "define.h"
#include "parse_cmdline.h"
#include "xilter.h"

int main(int argc, char **argv)
{
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.ifindex = -1,
		.run_mode = ATTACH,
	};
	parse_cmdline(argc, argv, &cfg);

	xilter(cfg);

	return 0;
}

