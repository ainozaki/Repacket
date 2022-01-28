CC = clang++

CPPFLAGS = -std=c++2a -I./
BPFFLAGS = -I../deps/include/ -I../deps/include/bpf
LFLAGS = -L../deps/lib
LIBS = -l:libbpf.a -lelf
XAPTURE_SRC=\
	base/parse_cmdline.cc \
	core/gen/generator.cc \
	core/xdp/loader.cc \
	core/xdp/perf_handler.cc
XAPTURE_H = $(XAPTURE_SRC:.cc=.h)
XAPTURE_OBJ=$(XAPTURE_SRC:.cc=.o) xapture.o

HEADER_ONLY = \
	base/config.h \
	base/logger.h \
	core/gen/xdp_base.h

.PHONY: all
.PHONY: clean

all: $(XAPTURE_OBJ) Makefile
	$(CC) $(CPPFLAGS) $(LFLAGS) -o xapture $(XAPTURE_OBJ) $(LIBS)

$(XAPTURE_OBJ): %.o: %.cc
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

format: $(XAPTURE_SRC) $(XAPTURE_H) $(HEADER_ONLY)
	clang-format -i $^ xapture.cc
clean:
	find ./ -name "*.o" -type f -delete
	rm -f xapture xdp-generated-kern.o xdp-generated-kern.ll
