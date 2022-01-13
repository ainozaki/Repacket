#include "core/gen/generator.h"

#include <stdio.h>
#include <stdlib.h>

#include "base/config.h"
#include "base/logger.h"
#include "core/gen/xdp_base.h"

int gen(const struct config* cfg) {
  FILE* f;

  f = fopen("xdp-generated-kern.c", "w");
  if (!f) {
    LOG_ERROR("Err: cannot open xdp_generated.c\n");
    return 1;
  }

  fprintf(f, include);
  fprintf(f, define_struct);

  char filter[1024];
  switch (cfg->run_mode) {
    case FILTER:
      sprintf(filter, filter_base, "iph->protocol == IPPROTO_ICMP");
      fprintf(f, sec, filter);
      break;
    default:
      // case DUMPALL
      fprintf(f, sec, "");
  }
  fprintf(f, license);

  fclose(f);

  // compile XDP code using clang.
  int err;
  err = system(
      "clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../deps/include/ -I../deps/include/bpf \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o xdp-generated-kern.ll xdp-generated-kern.c");
  if (err) {
    LOG_ERROR("Err cannot compile\n");
    return 1;
  }
  err = system(
      "llc -march=bpf -filetype=obj -o xdp-generated-kern.o "
      "xdp-generated-kern.ll");
  if (err) {
    LOG_ERROR("Err cannot llc\n");
    return 1;
  }
  LOG_INFO("Success: Compile completed.\n");

  return 0;
}
