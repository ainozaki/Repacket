CLANG := clang
LLC := llc

XDP_C := xdms.c
XDP_OBJ := $(XDP_C:.c=.o)
USER := main.cc
USER += controller.cc
USER += loader.cc
USER += map.cc
USER += utils.cc
USER_OBJ := $(USER:.cc=)

OBJECT_LIBBPF := ../libbpf/src/libbpf.a

LDFLAGS ?= -L../build/deps/lib
LIBS := -l:libbpf.a -lelf

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

loader: $(USER)
	 g++ -Wall $(BPF_CFLAGS) $(CFLAGS) -o loader $(LDFLAGS) $^ $(LIBS)

load:
	./loader

load-pass:
	./loader --sec xdp_pass

load-ip:
	ip link set dev eth1 xdpgeneric obj kern.o sec xdp

unload:
	./loader -unload

ping:
	ip netns exec router ping 172.16.10.1

format:
	find ./ -iname "*.cc" -o -iname "*.h" | xargs clang-format -i

clean:
	rm -rf *.o *.ll $(USER_OBJ)

