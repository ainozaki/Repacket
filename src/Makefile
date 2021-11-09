SRCS := xdpidms.c

OBJS := $(SRCS:.c=.o)

TARGET := xdpidms

OBJECT_LIBBPF := ../libbpf/src/libbpf.a

$(TARGET): $(SRCS)
	clang -O2 -g -Wall -target bpf -c $(SRCS) -o $(OBJS)

loader:
	 g++ -Wall -g -L../libbpf/src/ -o xdp_loader xdp_loader.cc -l:libbpf.a -lelf

libbpf:
	cd ../libbpf/src
	make all OBJDIR=.
	mkdir -p build
	make install_headers DESTDIR=build OBJDIR=.

run:
	./xdp_loader

unload:
	ip link set dev veth1 xdpgeneric off

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o xdp_loader

delete:
	ip -all netns del
