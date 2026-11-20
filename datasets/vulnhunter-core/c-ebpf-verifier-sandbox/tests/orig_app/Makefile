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

BUILD_DIR := build
CORE_SRCS := \
	src/cfg.c \
	src/bounds.c \
	src/verifier_mem.c \
	src/verifier.c \
	src/interp.c \
	src/loader.c

CORE_OBJS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS))
HDRS := include/bpf_vm.h

CLI_BIN := $(BUILD_DIR)/bpf_cli
TEST_SRCS := $(sort $(wildcard tests/*.c))
TEST_BINS := $(patsubst tests/%.c,$(BUILD_DIR)/tests/%,$(TEST_SRCS))

.PHONY: all test clean

all: $(CLI_BIN)

$(BUILD_DIR)/%.o: src/%.c $(HDRS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(CLI_BIN): $(CORE_OBJS) src/cli.c $(HDRS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) src/cli.c $(CORE_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/tests/%: tests/%.c $(CORE_OBJS) $(HDRS)
	@mkdir -p $(BUILD_DIR)/tests
	$(CC) $(CFLAGS) $< $(CORE_OBJS) -o $@ $(LDFLAGS)

test: $(CLI_BIN) $(TEST_BINS)
	@set -e; \
	for t in $(TEST_BINS); do \
		echo "[TEST] $$t"; \
		ASAN_OPTIONS="detect_leaks=1:exitcode=99:abort_on_error=0" \
		UBSAN_OPTIONS="print_stacktrace=1:exitcode=98:halt_on_error=1" \
		"./$$t"; \
	done

clean:
	rm -rf $(BUILD_DIR)
