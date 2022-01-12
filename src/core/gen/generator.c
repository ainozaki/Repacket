#include "core/gen/generator.h"

#include <stdio.h>
#include <stdlib.h>

#include "base/config.h"
#include "base/logger.h"
#include "core/gen/xdp_base.h"

int gen(const struct config *cfg){
	FILE *f;

	f = fopen("xdp-generated-kern.c", "w");
	if (!f){
		LOG_ERROR("Err: cannot open xdp_generated.c\n");
		return 1;
	}

	fprintf(f, include);
	fprintf(f, define_struct);
	fprintf(f, sec);
	fprintf(f, license);

	fclose(f);
	return 0;
}
