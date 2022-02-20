CC=clang++
CPPFLAGS=-std=c++2a -I./
BPFFLAGS=-I../deps/include/ -I../deps/include/bpf
LFLAGS=-L../deps/lib
LIBS=-l:libbpf.a -lelf
LIBS_TEST=-lgtest -lgtest_main

SRC=\
	base/parse_cmdline.cc \
	base/parse_rewrite_option.cc \
	base/utils.cc \
	core/gen/gen_controller.cc \
	core/gen/gen_dynamic.cc \
	core/xdp/loader.cc \
	core/xdp/map_handler.cc
HEADER=\
	base/config.h \
	base/logger.h \
	base/utils.h \
	base/parse_cmdline.h \
	base/parse_rewrite_option.h \
	core/gen/gen_controller.h \
	core/gen/gen_dynamic.h \
	core/gen/gen_static.h \
	core/xdp/loader.h
MAIN = repacket.cc

SRC_OBJ=$(SRC:.cc=.o)
MAIN_OBJ =$(MAIN:.cc=.o)
TARGET = repacket 
TEST_TARGET = test

TEST_SRC=\
	tests/parse_cmdline_unittest.cc \
	tests/parse_rewrite_option_unittest.cc
TEST_OBJ=$(TEST_SRC:.cc=.o)

.PHONY: all
all: $(SRC_OBJ) $(MAIN_OBJ)
	$(CC) $(LFLAGS) -o $(TARGET) $^ $(LIBS)

.PHONY: test
test: $(SRC_OBJ) $(TEST_OBJ)
	$(CC) $(LFLAGS) -o $(TEST_TARGET) $^ $(LIBS) $(LIBS_TEST) -pthread


$(SRC_OBJ): %.o: %.cc $(HEADER)
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

$(MAIN_OBJ): %.o: %.cc
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

$(TEST_OBJ): %.o: %.cc $(HEADER)
	$(CC) $(CPPFLAGS) $(BPFFLAGS) -o $(<:.cc=.o) -c $<

.PHONY: format
format: $(SRC) $(HEADER) $(TEST_SRC) $(MAIN)
	clang-format -i $^

.PHONY: clean
clean:
	rm -f $(SRC_OBJ) $(TEST_OBJ) $(MAIN_OBJ) $(TARGET) $(TEST_TARGET) xdp-generated-kern.o xdp-generated-kern.ll
