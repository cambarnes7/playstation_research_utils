PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
    CFLAGS += -DUSE_PS5_PAYLOAD_SDK
else
    CC ?= cc
endif

ELF := hv_bypass.elf

CFLAGS += -Wall -Werror -g -Iinclude

SRCS := src/main.c src/smn.c src/iommu.c src/hv_bypass.c

all: $(ELF)

$(ELF): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

.PHONY: all clean test
