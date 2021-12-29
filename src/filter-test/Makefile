CLANG := clang
LLC := llc

XDP_C := xdp_test_icmp_type.c
XDP_C += xdp_test_icmp_code.c
XDP_C += xdp_test_ip_protocol.c
XDP_C += xdp_test_ip_saddr.c
XDP_C += xdp_test_ip_tos.c
XDP_C += xdp_test_ip_tot_len_max.c
XDP_C += xdp_test_ip_tot_len_min.c
XDP_C += xdp_test_ip_ttl_max.c
XDP_C += xdp_test_ip_ttl_min.c
XDP_C += xdp_test_ip_ttl_min.c
XDP_C += xdp_test_tcp_dst.c
XDP_C += xdp_test_tcp_src.c
XDP_C += xdp_test_tcp_flags.c
XDP_C += xdp_test_udp_dst.c
XDP_C += xdp_test_udp_src.c
XDP_OBJ := $(XDP_C:.c=.o)

MAIN := main.cc
USER := moctok.cc
USER += base/bpf_wrapper.cc
USER += base/utils.cc
USER += base/yaml_handler.cc
USER += core/generator/generator.cc
USER += core/loader/loader.cc
USER += core/stats/map_handler.cc
USER += core/stats/stats.cc
USER_H := $(USER:.cc=.h)
USER_OBJ := $(USER:.cc=)
XILTER_OBJ := xilter

YAML := icmp_code.yaml
YAML += icmp_type.yaml
YAML += ip_protocol.yaml
YAML += ip_saddr.yaml
YAML += ip_tos.yaml
YAML += ip_tot_len_max.yaml
YAML += ip_tot_len_min.yaml
YAML += ip_ttl_max.yaml
YAML += ip_ttl_min.yaml
YAML += tcp_dst.yaml
YAML += tcp_src.yaml
YAML += tcp_flags.yaml
YAML += udp_dst.yaml
YAML += udp_src.yaml

TEST := base/yaml_handler_unittest.cc
TEST += filter-test/icmp.cc
TEST += filter-test/ip.cc
TEST += filter-test/tcp.cc
TEST += filter-test/udp.cc
TEST_OBJ := test

DATA := data/test.yaml

# for format
COMMON_H := base/define/define.h
COMMON_H += base/define/constant.h

LDFLAGS := -L../../deps/lib
LIBS := -l:libbpf.a -lelf -lyaml-cpp
LIBS_TEST := -lgtest -lgtest_main

CFLAGS := -I..
BPF_CFLAGS ?= -I../../deps/include/ -I../../deps/include/bpf

.SUFFIXES: .c .o

all:$(XDP_C) $(XDP_OBJ) $(YAML)
	echo $(XDP_C)

%.o: %.c
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(XDP_C):
	../xilter --gen --input icmp_type.yaml --output xdp_test_icmp_type.c
	../xilter --gen --input icmp_code.yaml --output xdp_test_icmp_code.c
	../xilter --gen --input ip_protocol.yaml --output xdp_test_ip_protocol.c
	../xilter --gen --input ip_saddr.yaml --output xdp_test_ip_saddr.c
	../xilter --gen --input ip_tos.yaml --output xdp_test_ip_tos.c
	../xilter --gen --input ip_tot_len_max.yaml --output xdp_test_ip_tot_len_max.c
	../xilter --gen --input ip_tot_len_min.yaml --output xdp_test_ip_tot_len_min.c
	../xilter --gen --input ip_ttl_max.yaml --output xdp_test_ip_ttl_max.c
	../xilter --gen --input ip_ttl_min.yaml --output xdp_test_ip_ttl_min.c
	../xilter --gen --input tcp_dst.yaml --output xdp_test_tcp_dst.c
	../xilter --gen --input tcp_src.yaml --output xdp_test_tcp_src.c
	../xilter --gen --input tcp_flags.yaml --output xdp_test_tcp_flags.c
	../xilter --gen --input udp_dst.yaml --output xdp_test_udp_dst.c
	../xilter --gen --input udp_src.yaml --output xdp_test_udp_src.c

clean:
	rm -rf *.o *.ll $(USER_OBJ) $(TEST_OBJ) $(XILTER_OBJ) $(XDP_C)
