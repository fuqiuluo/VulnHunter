CC      := gcc
CFLAGS  := -std=c11 -O2 -Wall -Wextra -Iinclude

BUILD_DIR := build
BINS      := $(BUILD_DIR)/sqe_sim $(BUILD_DIR)/sqe_disasm $(BUILD_DIR)/sqe_asm

.PHONY: all clean

all: $(BINS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/sqe_sim: src/sim_cli.c src/sqe_vm.c src/sqe_isa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/sqe_disasm: src/sqe_disasm.c src/sqe_vm.c src/sqe_isa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/sqe_asm: src/sqe_asm.c src/sqe_isa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(BUILD_DIR)
