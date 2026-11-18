CXX ?= g++
BASE_CXXFLAGS := -std=c++17 -Wall -Wextra -O1 -g -Iinclude

HAS_ASAN := $(shell printf 'int main(){return 0;}\n' | $(CXX) -fsanitize=address -x c++ - -o /dev/null 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAS_ASAN),1)
SAN_FLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
else
SAN_FLAGS ?=
endif

CXXFLAGS := $(BASE_CXXFLAGS) $(SAN_FLAGS)
LDFLAGS := $(SAN_FLAGS)

TARGET := build/frame_cli
SRCS := src/converter.cpp src/compositor.cpp src/cli.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) include/compositor.hpp
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf build
