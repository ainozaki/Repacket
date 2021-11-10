SRCS := xdpidms.c

OBJS := $(SRCS:.c=.o)

TARGET := xdpidms

OBJECT_LIBBPF := ../libbpf/src/libbpf.a

CFLAGS ?= -I../libbpf/src/build/usr/include
CFLAGS += -I./common
BPF_CFLAGS ?= -I../libbpf/src/build/usr/include

TUTORIAL_PATH := ../../tutorial-xdp/basic01-xdp-pass


$(TARGET): $(SRCS)
	cp ./xdpidms.c $(TUTORIAL_PATH)
	cd $(TUTORIAL_PATH); make
	mv $(TUTORIAL_PATH)/xdpidms.o ./
	#clang -S -target bpf $(BPF_CFLAGS) -g -Wall -O2 -c $(SRCS) -o $(OBJS)

loader:
	 g++ -std=c++11 -Wall $(CFLAGS) -g -L../libbpf/src/ -o xdp_loader xdp_loader.cc -l:libbpf.a -lelf

libbpf:
	cd ../libbpf/src
	make all OBJDIR=.
	mkdir -p build
	make install_headers DESTDIR=build OBJDIR=.

load:
	./xdp_loader

load-pass:
	./xdp_loader --sec xdp_pass

unload:
	./xdp_loader -unload

ping:
	ip netns exec router ping 172.16.10.1

clean:
	rm -rf *.o xdp_loader

delete:
	ip -all netns del

format:
	clang-format -i ./*.cc ./*.c
