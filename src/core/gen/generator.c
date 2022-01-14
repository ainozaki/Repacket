#include "core/gen/generator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/config.h"
#include "base/logger.h"
#include "core/gen/xdp_base.h"

int gen(const struct config* cfg) {
  FILE* f;

  f = fopen("xdp-generated-kern.c", "w");
  if (!f) {
    LOG_ERROR("Err: cannot open xdp-generated-kern.c\n");
    return 1;
  }

  // Generate XDP program.
  fprintf(f, include);
  fprintf(f, define_struct);

  char filter[1024] = "";
  char buff[128] = "";
  switch (cfg->run_mode) {
    case FILTER:
      filter_conditional_statement(cfg, buff);
      sprintf(filter, filter_base, buff);
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

void filter_conditional_statement(const struct config* cfg, char buf[]) {
  char ip_proto[32] = "";
  char tcp_dst[32] = "";
  char empty[32] = "";
  char* attributes[] = {ip_proto, tcp_dst};

  // If config has filtering attributes, convert them into string.
  if (strncmp(cfg->filter->ip_proto, empty, sizeof(cfg->filter->ip_proto))) {
    sprintf(ip_proto, "iph->protocol==%s", cfg->filter->ip_proto);
  }
  if (strncmp(cfg->filter->tcp_dst, empty, sizeof(cfg->filter->tcp_dst))) {
    sprintf(tcp_dst, "tcph->dest==%s", cfg->filter->tcp_dst);
  }

  // Concatinate conditional statements.
  char* ptr = buf;
  for (int i = 0; i < sizeof(attributes) / sizeof(char*); i++) {
    if (strncmp(attributes[i], empty, sizeof(attributes[i]))) {
      // strcpy copies until the end-NULL-byte.
      // strlen doesn't include the end-NULL-byte.
      strcpy(ptr, attributes[i]);
      ptr += strlen(attributes[i]);
      strcpy(ptr, "|");
      ptr++;
    }
  }
  memset(ptr - 1, '\0', 1);
  return;
}
