CLANG := clang
LLC := llc

XDP_C := xdp-generated-dump.c
XDP_OBJ := $(XDP_C:.c=.o)

MAIN := main.c
USER_TARGETS := parse_cmdline
USER_H := $(USER_TARGETS:=.h)
USER_C := $(USER_TARGETS:=.c)
USER_OBJ := $(USER_TARGETS:=.o)
XILTER_OBJ := xilter

TEST := parse_cmdline_unittest.cc

LDFLAGS := -L../deps/lib
LIBS := -l:libbpf.a -lelf -lyaml-cpp
LIBS_TEST := -lgtest -lgtest_main

CFLAGS := std=c++14 -Wall -I.
BPF_INCLUIDE ?= -I../deps/include/ -I../deps/include/bpf

all: $(XDP_OBJ) $(USER_TARGETS)

$(USER_TARGETS): %: %.c
	$(CC) -Wall $(BPF_INCLUDE) $(CFLAGS) $(LDFLAGS) -o $@ $< $(MAIN) $(LIBS)

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

test: $(TEST) $(USER_OBJ)
	 g++ -std=c++14 -Wall $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS) $(LIBS_TEST) -pthread

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
	rm -rf *.o *.ll
