
PS5_HOST ?= ?
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -Werror

all: kldload.elf

kldload.elf:
	$(CC) -o $@ main.c kekcall.asm -O0
	strip $@

clean:
	rm -f *.o *.elf

test: kldload.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

