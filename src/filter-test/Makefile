CLANG := clang
LLC := llc

XDP_C := xdp-generated.c
XDP_OBJ := $(XDP_C:.c=.o)

MAIN := main.cc
USER := moctok.cc
USER += base/bpf_wrapper.cc
USER += base/utils.cc
USER += base/yaml_handler.cc
USER += core/generator/generator.cc
USER += core/loader/loader.cc
USER += core/stats/map_handler.cc
USER += core/stats/stats.cc
USER_H := $(USER:.cc=.h)
USER_OBJ := $(USER:.cc=)
LOADER_OBJ := loader

TEST := base/yaml_handler_unittest.cc
TEST += filter-test/icmp_test.cc
TEST_OBJ := test

DATA := data/test.yaml

# for format
COMMON_H := base/define/define.h
COMMON_H += base/define/constant.h

LDFLAGS := -L../../deps/lib
LIBS := -l:libbpf.a -lelf -lyaml-cpp
LIBS_TEST := -lgtest -lgtest_main

CFLAGS := -I..
BPF_CFLAGS ?= -I../../deps/include/ -I../../deps/include/bpf

$(XDP_OBJ): $(XDP_C)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(XDP_C):
	../loader --gen icmp.yaml 

clean:
	rm -rf *.o *.ll $(USER_OBJ) $(TEST_OBJ) $(LOADER_OBJ) $(XDP_C)
