# prosperous_port - PS5 HV Bypass Exploit for FW 4.03
#
# Port of fail0verflow's "prosperous" exploit chain.
#
# Requires PS5_PAYLOAD_SDK environment variable to be set.
# Optional: aarch64-linux-gnu-gcc for rebuilding the MP4 payload.

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is not set)
endif

ELF     = prosperous_port.elf
ODIR    = build

# PS5 deployment settings
PS5_HOST ?= ps5
PS5_PORT ?= 9021

CFLAGS  += -Wall -Werror -g -Iinclude
LDFLAGS +=

# Source files
SRCS    = src/main.c \
          src/tmr.c \
          src/mp4_inject.c \
          src/deci5s.c \
          src/vmcb_patch.c

OBJS    = $(patsubst %.c,$(ODIR)/%.o,$(SRCS))

.PHONY: all clean test mp4_payload kpayload

all: $(ELF)

$(ODIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(ELF): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Build the MP4 AArch64 payload (requires aarch64 cross-compiler)
mp4_payload:
	$(MAKE) -C mp4_payload

# Build the kernel RPC payload (requires host g++ with znver2 support)
kpayload:
	$(MAKE) -C kpayload

# Deploy to PS5
test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

# Debug via GDB
debug: $(ELF)
	gdb \
		-ex "target extended-remote $(PS5_HOST):$(shell expr $(PS5_PORT) + 1)" \
		-ex "file $(ELF)" \
		-ex "remote put $(ELF) /data/$(ELF)" \
		-ex "set remote exec-file /data/$(ELF)" \
		-ex "start"

clean:
	rm -rf $(ODIR) $(ELF)
	$(MAKE) -C mp4_payload clean
	$(MAKE) -C kpayload clean
