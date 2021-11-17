CLANG := clang
LLC := llc

XDP_C := xdpidms.c
XDP_OBJ := $(XDP_C:.c=.o)
USER := loader.cc
USER_OBJ := $(USER:.cc=)

OBJECT_LIBBPF := ../libbpf/src/libbpf.a

LDFLAGS ?= -L../build/deps/lib
LIBS = -l:libbpf.a -lelf

CFLAGS += -I./common
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

loader: $(USER)
	 g++ -Wall $(BPF_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $(USER_OBJ) $< $(LIBS)

load:
	./loader

load-pass:
	./loader --sec xdp_pass

load-ip:
	ip link set dev eth1 xdpgeneric obj kern.o sec xdp

unload:
	./xdp_loader -unload

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o *.ll $(USER_OBJ)

