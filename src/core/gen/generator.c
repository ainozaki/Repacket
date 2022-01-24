#include "core/gen/generator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/config.h"
#include "base/logger.h"
#include "core/gen/xdp_base.h"

int gen(const struct config* cfg) {
  FILE* f;
  int err;

  f = fopen("xdp-generated-kern.c", "w");
  if (!f) {
    LOG_ERROR("Err: cannot open xdp-generated-kern.c\n");
    return 1;
  }

  // Generate XDP program.
  fprintf(f, include);
  fprintf(f, define_struct);

  char parse[1024] = "";
  char action[1024] = "";
  char buff[128] = "";
  char buff2[256] = "";
  switch (cfg->run_mode) {
    case FILTER:
      LOG_INFO("FILTER mode.\n");
      filter_conditional_statement(cfg, buff);
      sprintf(action, filter_base, buff, "XDP_PASS");
      sprintf(parse, parse_base, action);
      break;
    case REWRITE:
      LOG_INFO("REWRITE mode.\n");
      fprintf(f, always_inline);
      rewrite_statement(cfg, buff, buff2);
      sprintf(action, rewrite_base, buff, buff2);
      sprintf(parse, parse_base, action);
      break;
    case DROP:
      LOG_INFO("DROP mode.\n");
      filter_conditional_statement(cfg, buff);
      sprintf(action, filter_base, buff, "XDP_DROP");
      sprintf(parse, parse_base, action);
      break;
    default:
      // case DUMPALL
      LOG_INFO("DUMPALL mode.\n");
      break;
  }
  fprintf(f, sec_base, parse);
  fprintf(f, license);

  fclose(f);

  err = compile();
  if (err) {
    LOG_ERROR("Err while compiling xdp-generated-kern.c\n");
  }
  return err;
}

int compile() {
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
  char ip_proto[64] = "";
  char tcp_dst[64] = "";
  char empty[64] = "";
  char* attributes[] = {ip_proto, tcp_dst};

  // If config has filtering attributes, convert them into string.
  if (strncmp(cfg->filter->ip_proto, empty, sizeof(cfg->filter->ip_proto))) {
    sprintf(ip_proto, "iph && iph->protocol!=%s", cfg->filter->ip_proto);
  }
  if (strncmp(cfg->filter->tcp_dst, empty, sizeof(cfg->filter->tcp_dst))) {
    sprintf(tcp_dst, "tcph && tcph->dest!=%s", cfg->filter->tcp_dst);
  }

  // Concatinate conditional statements.
  char* ptr = buf;
  for (int i = 0; i < sizeof(attributes) / sizeof(char*); i++) {
    if (strncmp(attributes[i], empty, sizeof(attributes[i]))) {
      // strcpy copies until the end-NULL-byte.
      // strlen doesn't include the end-NULL-byte.
      strcpy(ptr, attributes[i]);
      ptr += strlen(attributes[i]);
      strcpy(ptr, "&&");
      ptr += 2;
    }
  }
  memset(ptr - 2, '\0', 2);
  return;
}

void rewrite_statement(const struct config* cfg, char buf[], char buf2[]) {
  char empty[64] = "";
  int use_ip = 0;
  int use_tcp = 0;
  int use_udp = 0;

  const struct filter* filter = cfg->filter;

  // If config has filtering attributes, convert them into string.
  // ip_ttl
  if (strncmp(filter->ip_ttl, empty, sizeof(filter->ip_ttl))) {
    use_ip = 1;
    const char* ip_ttl =
        "iph->ttl = %s;\n"
        "iph->check = 0;"
        "__u32 csum = 0;"
        "calc_csum(iph, sizeof(struct iphdr), &csum);"
        "iph->check = csum;\n";
    sprintf(buf2, ip_ttl, filter->ip_ttl);
  }

  // tcp_dst
  if (strncmp(filter->tcp_dst, empty, sizeof(filter->tcp_dst))) {
    use_tcp = 1;
    const char* tcp_dst =
        "unsigned long sum = bpf_ntohs(tcph->check) + bpf_ntohs(tcph->dest) + "
        "((~%s & 0xffff) + 1);\n"
        "tcph->check = bpf_htons(sum & 0xffff);"
        "tcph->dest = bpf_htons(%s);\n";
    sprintf(buf2, tcp_dst, filter->tcp_dst, filter->tcp_dst);
  }

  // udp_dst
  if (strncmp(filter->udp_dst, empty, sizeof(filter->udp_dst))) {
    use_udp = 1;
    const char* udp_dst = "udph->dest = bpf_htons(%s);\n";
    sprintf(buf2, udp_dst, filter->udp_dst);
  }

  // Prevent NULL pointer access.
  if (use_ip) {
    strncpy(buf, "iph", 4);
  } else if (use_tcp) {
    strncpy(buf, "tcph", 5);
  } else if (use_udp) {
    strncpy(buf, "udph", 5);
  }
  return;
}
