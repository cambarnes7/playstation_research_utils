#   GPU DMA probe payload for PS5 FW 4.03
#   Based on PS5 Payload SDK (John Törnblom)

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := gpu_dma.elf

CFLAGS := -Wall -Werror -g

all: $(ELF)

$(ELF): src/*.c
		$(CC) $(CFLAGS) -o $@ $^

clean:
		rm -f $(ELF)

test: $(ELF)
		$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
