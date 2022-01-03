#include "xilter.h"

#include <assert.h>

#include "define.h"
#include "loader.h"

void xilter(struct config cfg)
{
	switch (cfg.run_mode){
		case ATTACH:
			// Attach BPF program.
			attach(cfg.xdp_flags, cfg.ifindex, cfg.ifname);
			return;
		case DETACH:
			// Detach BPF program.
			detach(cfg.ifindex, cfg.ifname);
			return;
		default:
			assert(false);
	}
	return;
}
