CXX ?= g++
JAVAC ?= javac

JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(command -v $(JAVAC)))))
JNI_INCLUDES := -I"$(JAVA_HOME)/include" -I"$(JAVA_HOME)/include/linux"
AVX512_CXXFLAGS := -O2 -Wall -Wextra -shared -fPIC -mavx512f -mavx512bw -mavx512vbmi -mbmi2
COMPAT_HEADER := /usr/local/include/avx512_host_compat.h
SIM_CXXFLAGS := -O2 -Wall -Wextra -Wno-psabi -shared -fPIC -mbmi2 -include $(COMPAT_HEADER)

CLASSES_DIR := build/classes
NATIVE_LIB := build/libb64avx512.so
SIM_LIB := build/sim/libb64avx512.so
CLI_WRAPPER := build/b64_cli

JAVA_SRCS := $(wildcard src/codec/*.java)
NATIVE_SRCS := native/base64_avx512.cpp

.PHONY: all clean

all: $(NATIVE_LIB) $(CLI_WRAPPER)

$(NATIVE_LIB): $(NATIVE_SRCS)
	@mkdir -p build
	$(CXX) $(AVX512_CXXFLAGS) $(JNI_INCLUDES) $(NATIVE_SRCS) -o $(NATIVE_LIB)
	@if [ -f "$(COMPAT_HEADER)" ]; then \
		mkdir -p build/sim && \
		$(CXX) $(SIM_CXXFLAGS) $(JNI_INCLUDES) $(NATIVE_SRCS) -o $(SIM_LIB); \
	fi

$(CLI_WRAPPER): $(JAVA_SRCS) $(NATIVE_LIB)
	@mkdir -p $(CLASSES_DIR)
	$(JAVAC) -d $(CLASSES_DIR) $(JAVA_SRCS)
	@printf '%s\n' \
		'#!/usr/bin/env bash' \
		'set -euo pipefail' \
		'DIR="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"' \
		'JAVA_BIN="$$(readlink -f "$$(command -v java)")"' \
		'LIB_DIR="$$DIR"' \
		'if ! grep -qw avx512vbmi /proc/cpuinfo 2>/dev/null && [ -f "$$DIR/sim/libb64avx512.so" ]; then' \
		'    LIB_DIR="$$DIR/sim"' \
		'fi' \
		'JVM_ARGS=(--enable-native-access=ALL-UNNAMED -Xcheck:jni "-Djava.library.path=$$LIB_DIR" -cp "$$DIR/classes" codec.CodecCli "$$@")' \
		'if grep -qw avx512vbmi /proc/cpuinfo 2>/dev/null || [ "$$LIB_DIR" = "$$DIR/sim" ]; then' \
		'    exec "$$JAVA_BIN" "$${JVM_ARGS[@]}"' \
		'elif command -v qemu-x86_64 >/dev/null 2>&1; then' \
		'    exec qemu-x86_64 -cpu max "$$JAVA_BIN" -XX:TieredStopAtLevel=1 "$${JVM_ARGS[@]}"' \
		'else' \
		'    exec "$$JAVA_BIN" "$${JVM_ARGS[@]}"' \
		'fi' > $(CLI_WRAPPER)
	@chmod +x $(CLI_WRAPPER)

clean:
	rm -rf build
