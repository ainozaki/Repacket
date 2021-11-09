SRCS := xdpidms.c

OBJS := $(SRCS:.c=.o)

TARGET := xdpidms

OBJECT_LIBBPF := ../libbpf/src/libbpf.a

CFLAGS ?= -I../libbpf/src/build/usr/include
CFLAGS += -I./common
BPF_CFLAGS ?= -I../libbpf/src/build/usr/include

$(TARGET): $(SRCS)
	clang -S -target bpf $(BPF_CFLAGS) -g -Wall -O2 -c $(SRCS) -o $(OBJS)

loader:
	 g++ -Wall $(CFLAGS) -g -L../libbpf/src/ -o xdp_loader xdp_loader.cc -l:libbpf.a -lelf

libbpf:
	cd ../libbpf/src
	make all OBJDIR=.
	mkdir -p build
	make install_headers DESTDIR=build OBJDIR=.

load:
	./xdp_loader

unload:
	./xdp_loader -unload

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o xdp_loader

delete:
	ip -all netns del
