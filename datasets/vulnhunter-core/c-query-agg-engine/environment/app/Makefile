ifeq ($(origin CC),default)
  ifeq ($(shell printf 'int main(void){return 0;}\n' | gcc -fsanitize=address,undefined -x c - -o /dev/null 2>/dev/null && echo 1 || echo 0),1)
    CC := gcc
  else ifeq ($(shell printf 'int main(void){return 0;}\n' | clang -fsanitize=address,undefined -x c - -o /dev/null 2>/dev/null && echo 1 || echo 0),1)
    CC := clang
  else
    CC := gcc
  endif
endif

BASE_CFLAGS := -std=c11 -Wall -Wextra -O1 -g -Iinclude

HAS_SAN := $(shell printf 'int main(void){return 0;}\n' | $(CC) -fsanitize=address,undefined -x c - -o /dev/null 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAS_SAN),1)
SAN_FLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
else
SAN_FLAGS ?=
endif

CFLAGS := $(BASE_CFLAGS) $(SAN_FLAGS)
LDFLAGS := $(SAN_FLAGS)

TARGET := build/agg_cli
SRCS := src/lexer.c src/parser.c src/table.c src/planner.c src/hash_group.c src/exec.c src/cli.c
HDRS := include/engine.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf build
