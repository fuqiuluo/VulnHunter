CC ?= gcc
BASE_CFLAGS := -std=c11 -Wall -Wextra -O1 -g -fno-omit-frame-pointer -Iinclude

HAS_ASAN := $(shell printf 'int main(void){return 0;}\n' | $(CC) -fsanitize=address,undefined -x c - -o /dev/null 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAS_ASAN),1)
SAN_FLAGS ?= -fsanitize=address,undefined
else
SAN_FLAGS ?=
endif

CFLAGS := $(BASE_CFLAGS) $(SAN_FLAGS)
LDFLAGS := $(SAN_FLAGS)

TARGET := build/kex_cli
SRCS := \
	src/sha256_hkdf.c \
	src/packet.c \
	src/frag.c \
	src/sa_table.c \
	src/rekey.c \
	src/state_machine.c \
	src/cli.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) include/kex_engine.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf build
