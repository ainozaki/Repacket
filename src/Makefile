CC = gcc
AR = ar
LLC = llc
PROG = xapture

BPF_INCL = -I../deps/include/ -I../deps/include/bpf
CFLAGS = -I. $(BPF_INCL) -g -O2 -Wall
LDFLAGS = -L../deps/lib
LIBS = -l:libbpf.a -lelf
LIBS_TEST = -lgtest -lgtest_main

XDP_SRC:=xdp-generated-kern.c
XDP_OBJ:=$(XDP_SRC:.c=.o)

C_SRC = xapture.c
C_OBJ = $(C_SRC:.c=.o)

LIBXAPTURE_SRC=\
	base/parse_cmdline.c \
	core/dump/print_ether.c \
	core/dump/print_icmp.c \
	core/dump/print_ip.c \
	core/xdp/loader.c \
	core/xdp/perf_event_handler.c
LIBXAPTURE_OBJ=$(LIBXAPTURE_SRC:.c=.o)
LIBXAPTURE=libxapture.a

HDRS=\
	core/dump/binary_utils.h \
	core/dump/def/ip.h \
	core/dump/def/ether.h \
	core/dump/def/types.h

TEST := tests/parse_cmdline_unittest.cc

all: $(PROG) $(LIBXAPTURE_SRC) $(C_SRC) $(HDRS)

$(PROG): $(C_OBJ) $(LIBXAPTURE) $(HDRS)
	rm -f $@
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(C_OBJ) $(LIBXAPTURE) $(LIBS)

$(LIBXAPTURE): $(LIBXAPTURE_OBJ)
	rm -f $@
	$(AR) cr $@ $(LIBXAPTURE_OBJ)

$(LIBXAPTURE_OBJ): %.o: %.c $(HDRS)
	$(CC) -c $(CFLAGS) $< -o $@

$(C_OBJ): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

xdp: $(XDP_SRC)
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_INCL) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o $(XDP_OBJ:.o=.ll) $<
	$(LLC) -march=bpf -filetype=obj -o $(XDP_OBJ) $(XDP_OBJ:.o=.ll)

run:
	sudo ./xapture -i eth1

off:
	sudo ./xapture -i eth1 -d

#test: $(TEST)
#	gcc -Wall $(BPF_INCLUDE) $(CFLAGS) -c $(USER_C)
#	g++ -std=c++14 -Wall $(CFLAGS) $(LDFLAGS) -o $@ $^ $(USER_OBJ) $(LIBS) $(LIBS_TEST) -pthread

format:
	clang-format -i $(LIBXAPTURE_SRC) $(C_SRC)

clean:
	rm -f $(LIBXAPTURE) $(XDP_OBJ:.o=.ll) $(PROG)
	find ./ -name "*.o" -type f -delete
