CC ?= cc
AR ?= ar
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L -D_FILE_OFFSET_BITS=64 -Iinclude
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
LDFLAGS ?=
BUILD ?= build
WRAPS = -Wl,--wrap=pwrite -Wl,--wrap=pwrite64 -Wl,--wrap=pread -Wl,--wrap=pread64 -Wl,--wrap=fdatasync

.PHONY: all test check adversarial sanitize clean

all: $(BUILD)/crashlog $(BUILD)/libcrashlog.a

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/crashlog.o: src/crashlog.c include/crashlog.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c src/crashlog.c -o $@

$(BUILD)/libcrashlog.a: $(BUILD)/crashlog.o
	$(AR) rcs $@ $<

$(BUILD)/crashlog: src/main.c $(BUILD)/libcrashlog.a include/crashlog.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/main.c $(BUILD)/libcrashlog.a $(LDFLAGS) -o $@

$(BUILD)/test_crashlog: tests/test_crashlog.c $(BUILD)/libcrashlog.a include/crashlog.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_crashlog.c $(BUILD)/libcrashlog.a $(WRAPS) $(LDFLAGS) -o $@

test check: $(BUILD)/crashlog $(BUILD)/test_crashlog
	./$(BUILD)/test_crashlog
	python3 tests/test_wire.py ./$(BUILD)/crashlog

$(BUILD)/shared_handle_boundary: tests/shared_handle_boundary.c $(BUILD)/libcrashlog.a include/crashlog.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/shared_handle_boundary.c $(BUILD)/libcrashlog.a -Wl,--wrap=pwrite -Wl,--wrap=pwrite64 $(LDFLAGS) -o $@

adversarial: $(BUILD)/crashlog $(BUILD)/shared_handle_boundary
	python3 tests/adversarial_review.py ./$(BUILD)/crashlog
	./$(BUILD)/shared_handle_boundary

sanitize:
	$(MAKE) BUILD=build-sanitize CC=clang CFLAGS='-std=c11 -O1 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' test

clean:
	rm -rf build build-sanitize build-clang
