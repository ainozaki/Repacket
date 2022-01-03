#include "parse_cmdline.h"

#include <stdio.h>
#include <unistd.h>

#include "define.h"

void parse_cmdline(int argc, char **argv, struct config *cfg)
{
	int opt;
	while ((opt = getopt(argc, argv, "d::")) != -1){
			switch (opt){
				case 'd':
					cfg->run_mode = DETACH;
					break;
				default:
					printf("unknown cmdline option.\n");
			}
	}
}

