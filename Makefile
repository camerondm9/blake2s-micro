
CFLAGS_COMMON = -Wall -Werror -Os -std=c99 -fno-unroll-loops
CFLAGS = $(CFLAGS_COMMON) -g
CFLAGS_ARM = $(CFLAGS_COMMON) -mthumb -nostdlib -T test-mcu.ld

.PHONY: all run clean

all: build/test build/sizetest_m0 build/sizetest_m4

run: build/test
	@$<

test: build/test
	@./test.py

clean:
	rm -rf build

build/test: blake2s.c test.c
	@mkdir -p build
	$(CC) $(CFLAGS) -DDEBUG -o $@ $^

build/sizetest_m0: blake2s.c test-stdlib.c test-mcu.c
	@mkdir -p build
	@arm-none-eabi-gcc $(CFLAGS_ARM) -mcpu=cortex-m0 -o $@ $^
	@arm-none-eabi-size $@

build/sizetest_m4: blake2s.c test-stdlib.c test-mcu.c
	@mkdir -p build
	@arm-none-eabi-gcc $(CFLAGS_ARM) -mcpu=cortex-m4 -o $@ $^
	@arm-none-eabi-size $@
