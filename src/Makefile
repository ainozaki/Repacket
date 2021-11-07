SRCS := xdpidms.c

OBJS := $(SRCS:.c=.o)

TARGET := xdpidms

$(TARGET): $(SRCS)
	clang -O2 -g -Wall -target bpf -c $(SRCS) -o $(OBJS)

clean:
	rm -rf *.o
