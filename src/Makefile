CLANG := clang
LLC := llc

XDP_C := xdp-generated.c
XDP_OBJ := $(XDP_C:.c=.o)

MAIN := main.cc
USER := controller.cc
USER += generator.cc
USER += loader.cc
USER += map.cc
USER += utils.cc
USER_OBJ := $(USER:.cc=)
LOADER_OBJ := loader

TEST := generator_unittest.cc
TEST_OBJ := test

# for format
COMMON_H := common/define.h
COMMON_H += common/constant.h

LDFLAGS := -L../build/deps/lib
LIBS := -l:libbpf.a -lelf -lyaml-cpp
LIBS_TEST := -lgtest -lgtest_main

CFLAGS := -I./common
BPF_CFLAGS ?= -I../build/deps/include/bpf

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

loader: $(USER) $(COMMON_H) $(MAIN) common/xdp_base.h
	 g++ -Wall $(BPF_CFLAGS) $(CFLAGS) -o $(LOADER_OBJ) $(LDFLAGS) $^ $(LIBS)

test: $(TEST) $(USER)
	 g++ -std=c++11 -Wall $(BPF_CFLAGS) $(CFLAGS) -o $(TEST_OBJ) $(LDFLAGS) $^ $(LIBS) $(LIBS_TEST) -pthread

format:
# to exclude "common/xdp_base.h", use first command.
	clang-format -i $(XDP_C) $(USER) $(USER:.cc=.h) $(TEST) $(COMMON) 
# find ./ -name "*.cc" -o -name "*.h" -o -path "./common" -name "xdp_base.h" -prune | xargs clang-format -i

load:
	./loader

load-pass:
	./loader --sec xdp_pass

load-ip:
	ip link set dev eth1 xdpgeneric obj kern.o sec xdp

gen:
	./loader --gen example.yaml 

unload:
	./loader -unload

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o *.ll $(USER_OBJ) $(TEST_OBJ) $(LOADER_OBJ) $(XDP_C)
