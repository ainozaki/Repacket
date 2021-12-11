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
USER += core/loader/moctok_filter.cc
USER += core/logger/map.cc
USER_H := $(USER:.cc=.h)
USER_OBJ := $(USER:.cc=)
LOADER_OBJ := loader

TEST := base/yaml_handler_unittest.cc
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

format:
# to exclude "common/xdp_base.h", use first command.
	clang-format -i $(USER) $(USER:.cc=.h) $(TEST) $(COMMON) main.cc $(XDP_C) 
# find ./ -name "*.cc" -o -name "*.h" -o -path "./common" | xargs clang-format -i

load:
	./loader --load

load-pass:
	./loader --sec xdp_pass

load-ip:
	ip link set dev eth1 xdpgeneric obj kern.o sec xdp

gen:
	./loader --gen moctok.yaml 

unload:
	./loader --unload

stats:
	./loader --stats

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o *.ll $(USER_OBJ) $(TEST_OBJ) $(LOADER_OBJ) $(XDP_C)
