CC = clang++

CPPFLAGS = -std=c++2a -I./
BPFFLAGS = -I../deps/include/ -I../deps/include/bpf
LFLAGS = -L../deps/lib
LIBS = -l:libbpf.a -lelf
LIBS_TEST = -lgtest -lgtest_main
XAPTURE_SRC=\
	base/parse_cmdline.cc \
	core/dump/binary_utils.cc \
	core/dump/print_arp.cc \
	core/dump/print_ether.cc \
	core/dump/print_icmp.cc \
	core/dump/print_ip.cc \
	core/dump/print_tcp.cc \
	core/dump/print_udp.cc \
	core/gen/generator.cc \
	core/xdp/loader.cc \
	core/xdp/map_handler.cc \
	core/xdp/perf_handler.cc
XAPTURE_H=\
	base/config.h \
	base/logger.h \
	base/parse_cmdline.h \
	core/dump/binary_utils.h \
	core/dump/print.h \
	core/gen/xdp_base.h \
	core/gen/generator.h \
	core/xdp/loader.h \
	core/xdp/perf_handler.h
XAPTURE_OBJ=$(XAPTURE_SRC:.cc=.o)
XAPTURE_O = xapture.o

TEST_SRC=\
	tests/parse_cmdline_unittest.cc

all: $(XAPTURE_OBJ) $(XAPTURE_H) $(XAPTURE_O) Makefile
	$(CC) $(CPPFLAGS) $(LFLAGS) -o xapture $(XAPTURE_OBJ) $(XAPTURE_O) $(LIBS)

test: $(XAPTURE_SRC) $(XAPTURE_H) $(TEST_SRC) Makefile
	$(CC) $(CPPFLAGS) $(BPFFLAGS) $(LFLAGS) -o test $(XAPTURE_SRC) $(TEST_SRC) $(LIBS) $(LIBS_TEST) -pthread

$(XAPTURE_OBJ): %.o: %.cc
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

$(XAPTURE_O): %.o: %.cc
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

format: $(XAPTURE_SRC) $(XAPTURE_H) $(HEADER_ONLY)
	clang-format -i $^ xapture.cc
clean:
	find ./ -name "*.o" -type f -delete
	rm -f xapture xdp-generated-kern.o xdp-generated-kern.ll test

.PHONY: all clean test format
