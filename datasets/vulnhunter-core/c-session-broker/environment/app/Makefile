CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2 -g
INCLUDES = -Iinclude

BUILD_DIR = build
TARGET    = $(BUILD_DIR)/broker_cli
SRCS      = src/negotiator.c src/template.c src/dispatcher.c src/cli.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) include/session_broker.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o $(TARGET)

clean:
	rm -rf $(BUILD_DIR)
