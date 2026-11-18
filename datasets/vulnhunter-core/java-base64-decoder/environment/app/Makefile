CXX ?= g++
JAVAC ?= javac

JAVA_HOME ?= $(shell dirname $$(dirname $$(readlink -f $$(command -v $(JAVAC)))))
JNI_INCLUDES := -I"$(JAVA_HOME)/include" -I"$(JAVA_HOME)/include/linux"
AVX512_CXXFLAGS := -O2 -Wall -Wextra -shared -fPIC -mavx512f -mavx512bw -mavx512vbmi -mbmi2

CLASSES_DIR := build/classes
NATIVE_LIB := build/libb64avx512.so
CLI_WRAPPER := build/b64_cli

JAVA_SRCS := $(wildcard src/codec/*.java)
NATIVE_SRCS := native/base64_avx512.cpp

.PHONY: all clean

all: $(NATIVE_LIB) $(CLI_WRAPPER)

$(NATIVE_LIB): $(NATIVE_SRCS)
	@mkdir -p build
	$(CXX) $(AVX512_CXXFLAGS) $(JNI_INCLUDES) $(NATIVE_SRCS) -o $(NATIVE_LIB)

$(CLI_WRAPPER): $(JAVA_SRCS) $(NATIVE_LIB)
	@mkdir -p $(CLASSES_DIR)
	$(JAVAC) -d $(CLASSES_DIR) $(JAVA_SRCS)
	@printf '%s\n' \
		'#!/usr/bin/env bash' \
		'set -euo pipefail' \
		'DIR="$$(cd "$$(dirname "$${BASH_SOURCE[0]}")" && pwd)"' \
		'JAVA_BIN="$$(readlink -f "$$(command -v java)")"' \
		'JVM_ARGS=(--enable-native-access=ALL-UNNAMED -Xcheck:jni "-Djava.library.path=$$DIR" -cp "$$DIR/classes" codec.CodecCli "$$@")' \
		'if grep -qw avx512vbmi /proc/cpuinfo 2>/dev/null; then' \
		'    exec "$$JAVA_BIN" "$${JVM_ARGS[@]}"' \
		'elif command -v qemu-x86_64 >/dev/null 2>&1; then' \
		'    exec qemu-x86_64 -cpu max "$$JAVA_BIN" -XX:TieredStopAtLevel=1 "$${JVM_ARGS[@]}"' \
		'else' \
		'    exec "$$JAVA_BIN" "$${JVM_ARGS[@]}"' \
		'fi' > $(CLI_WRAPPER)
	@chmod +x $(CLI_WRAPPER)

clean:
	rm -rf build
