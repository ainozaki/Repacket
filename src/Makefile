CC := gcc
LLC := llc

XDP_C := xdp-generated-kern.c
XDP_OBJ := $(XDP_C:.c=.o)

USER_TARGETS := loader
USER_TARGETS += parse_cmdline
USER_TARGETS += perf_event_handler
USER_TARGETS += print_ether
USER_TARGETS += xdump
USER_H := $(USER_TARGETS:=.h)
USER_C := $(USER_TARGETS:=.c)
USER_OBJ := $(USER_TARGETS:=.o)
MAIN := main.c
OBJ := dump
TEST := tests/parse_cmdline_unittest.cc

CFLAGS := -I./
BPF_INCLUDE ?= -I../deps/include/ -I../deps/include/bpf

LDFLAGS := -L../deps/lib
LIBS := -l:libbpf.a -lelf
LIBS_TEST := -lgtest -lgtest_main

user: $(USER_C)
	gcc -Wall $(BPF_INCLUDE) $(CFLAGS) $(LDFLAGS) -o xdump $^ $(MAIN) $(LIBS)

xdp: $(XDP_C)
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_INCLUDE) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${XDP_OBJ:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $(XDP_OBJ) ${XDP_OBJ:.o=.ll}

test: $(TEST)
	gcc -Wall $(BPF_INCLUDE) $(CFLAGS) -c $(USER_C)
	g++ -std=c++14 -Wall $(CFLAGS) $(LDFLAGS) -o $@ $^ $(USER_OBJ) $(LIBS) $(LIBS_TEST) -pthread

format:
	clang-format -i $(USER_H) $(USER_C) 

run:
	sudo ../src/xilter --attach
	sudo ./xdp-generated-dump

detach:
	../src/xilter --detach

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o *.ll xdump test
