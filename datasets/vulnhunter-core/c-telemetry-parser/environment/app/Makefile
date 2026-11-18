CC ?= gcc
BASE_CFLAGS := -Wall -Wextra -O1 -g -Iinclude

# Automatically enable ASan/UBSan when supported by the toolchain (e.g., inside Ubuntu Docker)
HAS_ASAN := $(shell printf 'int main(void){return 0;}\n' | $(CC) -fsanitize=address -x c - -o /dev/null 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAS_ASAN),1)
SAN_FLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
else
SAN_FLAGS ?=
endif

CFLAGS := $(BASE_CFLAGS) $(SAN_FLAGS)
LDFLAGS := $(SAN_FLAGS)

TARGET := build/pkt_cli
SRCS := src/pkt_parser.c src/cli.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) include/pkt_parser.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf build
