#include <linux/if_link.h>

#include "base/config.h"
#include "base/parse_cmdline.h"
#include "xapture.h"

int main(int argc, char **argv)
{
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.ifindex = -1,
		.run_mode = ATTACH,
	};
	parse_cmdline(argc, argv, &cfg);

	xdump(cfg);

	return 0;
}

