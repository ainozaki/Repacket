CC := gcc
LLC := llc

XDP_C := xdp-generated-dump.c
XDP_OBJ := $(XDP_C:.c=.o)

USER_TARGETS := parse_cmdline
USER_H := $(USER_TARGETS:=.h)
USER_C := $(USER_TARGETS:=.c)
USER_OBJ := $(USER_TARGETS:=.o)
MAIN := main.c
OBJ := dump
TEST := tests/parse_cmdline_unittest.cc

CFLAGS := -I./
BPF_INCLUDE ?= -I../deps/include/ -I../deps/include/bpf

LDFLAGS := -L../deps/lib
LIBS := -l:libbpf.a -lelf -lyaml-cpp
LIBS_TEST := -lgtest -lgtest_main

all: $(XDP_OBJ) $(USER_TARGETS)

$(USER_TARGETS): %: %.c
	gcc -Wall $(BPF_INCLUDE) $(CFLAGS) $(LDFLAGS) -o dump $< $(MAIN) $(LIBS)

$(XDP_OBJ): $(XDP_C)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_INCLUDE) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

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
	rm -rf *.o *.ll dump test
