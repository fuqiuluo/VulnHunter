CXX ?= g++
BASE_CXXFLAGS := -std=c++20 -Wall -Wextra -O1 -g -Iinclude

HAS_ASAN := $(shell printf 'int main(){return 0;}\n' | $(CXX) -std=c++20 -fsanitize=address,undefined -x c++ - -o /dev/null 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAS_ASAN),1)
SAN_FLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
else
SAN_FLAGS ?= -fno-omit-frame-pointer
endif

CXXFLAGS := $(BASE_CXXFLAGS) $(SAN_FLAGS)
LDFLAGS := $(SAN_FLAGS)

TARGET := build/mux_cli
SRCS := \
	src/timer_wheel.cpp \
	src/reassembler.cpp \
	src/flow_control.cpp \
	src/stream.cpp \
	src/connection.cpp \
	src/wire_codec.cpp \
	src/cli.cpp

HEADERS := include/mux_engine.hpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) $(HEADERS)
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf build
