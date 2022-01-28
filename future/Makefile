CC = clang++

CPPFLAGS = -std=c++17 -I./
XAPTURE_SRC=\
	base/parse_cmdline.cc \
	xapture.cc
XAPTURE_OBJ=$(XAPTURE_SRC:.cc=.o)

HEADER_ONLY = \
	base/config.h \
	base/logger.h

.PHONY: all
.PHONY: clean

all: $(XAPTURE_OBJ) Makefile
	$(CC) $(CPPFLAGS) -o xapture $(XAPTURE_OBJ)

$(XAPTURE_OBJ): %.o: %.cc
	$(CC) $(CPPFLAGS) -o $(<:.cc=.o) -c $<

format: $(XAPTURE_SRC) $(HEADER_ONLY)
	clang-format -i $^
clean:
	find ./ -name "*.o" -type f -delete
