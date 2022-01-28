CC = clang++

CPPFLAGS = -std=c++17 -I./
BPFFLAGS = -I../deps/include/ -I../deps/include/bpf
LFLAGS = -L../deps/lib
LIBS = -l:libbpf.a -lelf
XAPTURE_SRC=\
	base/parse_cmdline.cc \
	core/xdp/loader.cc \
	xapture.cc
XAPTURE_OBJ=$(XAPTURE_SRC:.cc=.o)

HEADER_ONLY = \
	base/config.h \
	base/logger.h

.PHONY: all
.PHONY: clean

all: $(XAPTURE_OBJ) Makefile
	$(CC) $(CPPFLAGS) $(LFLAGS) -o xapture $(XAPTURE_OBJ) $(LIBS)

$(XAPTURE_OBJ): %.o: %.cc
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

format: $(XAPTURE_SRC) $(HEADER_ONLY)
	clang-format -i $^
clean:
	find ./ -name "*.o" -type f -delete
