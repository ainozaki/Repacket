CLANG := clang
LLC := llc

XDP_C := xdp-generated.c
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
LOADER_OBJ := loader

TEST := base/yaml_handler_unittest.cc
TEST += filter-test/icmp.cc
TEST += filter-test/ip.cc
TEST += filter-test/tcp.cc
TEST_XDP_C := filter-test/xdp_test_icmp_type.c
TEST_XDP_C += filter-test/xdp_test_icmp_code.c
TEST_XDP_C += filter-test/xdp_test_ip_protocol.c
TEST_XDP_C += filter-test/xdp_test_ip_saddr.c
TEST_XDP_C += filter-test/xdp_test_ip_tos.c
TEST_XDP_C += filter-test/xdp_test_ip_tot_len_max.c
TEST_XDP_C += filter-test/xdp_test_ip_tot_len_min.c
TEST_XDP_C += filter-test/xdp_test_ip_ttl_max.c
TEST_XDP_C += filter-test/xdp_test_ip_ttl_min.c
TEST_XDP_C += filter-test/xdp_test_tcp_src.c
TEST_XDP_OBJ := $(TEST_XDP_C:.c=.o)
TEST_XDP_OBJ += $(TEST_XDP_C:.c=.ll)
TEST_OBJ := test

DATA := data/test.yaml

# for format
COMMON_H := base/define/define.h
COMMON_H += base/define/constant.h

LDFLAGS := -L../deps/lib
LIBS := -l:libbpf.a -lelf -lyaml-cpp
LIBS_TEST := -lgtest -lgtest_main

CFLAGS := -I.
BPF_CFLAGS ?= -I../deps/include/ -I../deps/include/bpf

$(XDP_OBJ): $(XDP_C)
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

moctok: $(USER) $(USER_H) $(COMMON_H) $(MAIN)
	 g++ -std=c++14 -Wall $(BPF_CFLAGS) $(CFLAGS) -o $(LOADER_OBJ) $(LDFLAGS) $^ $(LIBS)

test: $(TEST) $(USER)
	 g++ -std=c++14 -Wall $(BPF_CFLAGS) $(CFLAGS) -o $(TEST_OBJ) $(LDFLAGS) $^ $(LIBS) $(LIBS_TEST) -pthread
	 cd "$(PWD)/filter-test" && make

format:
# to exclude "common/xdp_base.h", use first command.
	clang-format -i $(USER) $(USER:.cc=.h) $(TEST) $(COMMON) main.cc $(XDP_C) 
# find ./ -name "*.cc" -o -name "*.h" -o -path "./common" | xargs clang-format -i

attach:
	./loader --attach

load-ip:
	ip link set dev eth1 xdpgeneric obj kern.o sec xdp

detach:
	./loader --detach

gen:
	./loader --gen 

stats:
	./loader --stats

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o *.ll $(USER_OBJ) $(TEST_OBJ) $(TEST_XDP_C) $(TEST_XDP_OBJ) $(LOADER_OBJ) $(XDP_C)
