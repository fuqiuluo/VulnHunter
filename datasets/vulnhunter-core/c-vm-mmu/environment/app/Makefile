CC      ?= gcc
AR      ?= ar
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L -Iinclude
LDFLAGS ?= -pthread

BUILD_DIR := build
LIB_OBJS  := \
	$(BUILD_DIR)/vmm_phys.o \
	$(BUILD_DIR)/vmm_image.o \
	$(BUILD_DIR)/vmm_tlb.o \
	$(BUILD_DIR)/vmm_mmu.o \
	$(BUILD_DIR)/vmm_fault.o \
	$(BUILD_DIR)/vmm_pin.o \
	$(BUILD_DIR)/vmm_trace.o

LIB_TARGET := $(BUILD_DIR)/libvmmmu.a
CLI_TARGET := $(BUILD_DIR)/mmu_cli

.PHONY: all clean

all: $(LIB_TARGET) $(CLI_TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	rm -f $@
	$(AR) rcs $@ $(LIB_OBJS)

$(CLI_TARGET): src/mmu_cli.c $(LIB_TARGET) | $(BUILD_DIR)
	$(CC) $(CFLAGS) src/mmu_cli.c $(LIB_TARGET) $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD_DIR)
