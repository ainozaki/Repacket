CC = clang++

CPPFLAGS = -std=c++2a -I./
BPFFLAGS = -I../deps/include/ -I../deps/include/bpf
LFLAGS = -L../deps/lib
LIBS = -l:libbpf.a -lelf
LIBS_TEST = -lgtest -lgtest_main
SRC=\
	base/parse_cmdline.cc \
	core/gen/gen_controller.cc \
	core/gen/gen_dynamic.cc \
	core/xdp/loader.cc \
	core/xdp/map_handler.cc
HEADER=\
	base/config.h \
	base/logger.h \
	base/parse_cmdline.h \
	core/gen/gen_controller.h \
	core/gen/gen_dynamic.h \
	core/gen/gen_static.h \
	core/xdp/loader.h
XAPTURE = xapture.cc
TEST_SRC=\
	tests/parse_cmdline_unittest.cc

OBJ=$(SRC:.cc=.o)
XAPTURE_OBJ=$(XAPTURE:.cc=.o)
TEST_OBJ=$(TEST_SRC:.cc=.o)

.PHONY: all
all: $(OBJ) $(XAPTURE_OBJ)
	$(CC) $(LFLAGS) -o xapture $^ $(LIBS)

.PHONY: test
test: $(OBJ) $(TEST_OBJ)
	$(CC) $(LFLAGS) -o test $^ $(LIBS) $(LIBS_TEST) -pthread


$(OBJ): %.o: %.cc $(HEADER)
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

$(XAPTURE_OBJ): %.o: %.cc
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

$(TEST_OBJ): %.o: %.cc $(HEADER)
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

.PHONY: format
format: $(SRC) $(HEADER) $(TEST_SRC) $(XAPTURE)
	clang-format -i $^ xapture.cc

.PHONY: clean
clean:
	rm -f $(OBJ) $(TEST_OBJ) $(XAPTURE_OBJ) xapture test xdp-generated-kern.o xdp-generated-kern.ll
