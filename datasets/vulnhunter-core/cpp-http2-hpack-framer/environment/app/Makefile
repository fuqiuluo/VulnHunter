ifeq ($(origin CXX),default)
  ifeq ($(shell printf 'int main(){return 0;}\n' | g++ -std=c++20 -fsanitize=address,undefined -x c++ - -o /dev/null 2>/dev/null && echo 1 || echo 0),1)
    CXX := g++
  else ifeq ($(shell printf 'int main(){return 0;}\n' | clang++ -std=c++20 -fsanitize=address,undefined -x c++ - -o /dev/null 2>/dev/null && echo 1 || echo 0),1)
    CXX := clang++
  else
    CXX := g++
  endif
endif

HAS_SAN := $(shell printf 'int main(){return 0;}\n' | $(CXX) -std=c++20 -fsanitize=address,undefined -x c++ - -o /dev/null 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAS_SAN),1)
SANFLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
else
SANFLAGS ?= -fno-omit-frame-pointer
endif

CXXFLAGS := -std=c++20 -O1 -g -Wall -Wextra -Iinclude $(SANFLAGS)
LDFLAGS  := $(SANFLAGS)

LIB_SRCS := \
	src/huffman.cpp \
	src/hpack_table.cpp \
	src/hpack_codec.cpp \
	src/header_validator.cpp \
	src/h2_connection.cpp

LIB_OBJS := $(patsubst src/%.cpp,build/%.o,$(LIB_SRCS))

.PHONY: all test clean

all: build/libh2framer.a build/smoke_test

build/%.o: src/%.cpp include/h2_framer.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/libh2framer.a: $(LIB_OBJS)
	ar rcs $@ $^

build/smoke_test: tests/smoke_test.cpp build/libh2framer.a
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $< build/libh2framer.a -o $@ $(LDFLAGS)

test: build/smoke_test
	./build/smoke_test

clean:
	rm -rf build
