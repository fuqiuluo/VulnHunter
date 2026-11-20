JAVAC      := javac
JAVA       := java
JFLAGS     := --release 21 -encoding UTF-8 -Xlint:deprecation

BUILD_DIR  := build
MAIN_OUT   := $(BUILD_DIR)/classes
TEST_OUT   := $(BUILD_DIR)/test-classes

MAIN_SRCS  := $(shell find src/main/java -name '*.java' | sort)
TEST_SRCS  := $(shell find src/test/java -name '*.java' | sort)

.PHONY: all compile-main compile-test test clean

all: compile-main compile-test

compile-main:
	@mkdir -p $(MAIN_OUT)
	$(JAVAC) $(JFLAGS) -d $(MAIN_OUT) $(MAIN_SRCS)

compile-test: compile-main
	@mkdir -p $(TEST_OUT)
	$(JAVAC) $(JFLAGS) -cp $(MAIN_OUT) -d $(TEST_OUT) $(TEST_SRCS)

test: all
	$(JAVA) -ea -cp $(MAIN_OUT):$(TEST_OUT) io.stonegate.federation.FederationTestSuite

clean:
	rm -rf $(BUILD_DIR)
