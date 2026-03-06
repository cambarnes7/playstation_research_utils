# Build flat binary payloads for PS5 kldload.elf
# These run as kernel threads — no libc, no relocations, entry at offset 0
#
# Usage:
#   make                    # build all .bin payloads
#   make rop_test.bin       # build just the ROP test
#   make reg_probe.bin      # build just the register probe

CC = clang
AS = $(CC)
OBJCOPY = objcopy

# Target: bare metal x86-64, no red zone (kernel code), no stdlib
ASFLAGS = -target x86_64-unknown-none -nostdlib -nostartfiles \
          -ffreestanding -mno-red-zone -c
LDFLAGS = -T flat.ld

all: rop_test.bin reg_probe.bin

# Assemble .S → .o
%.o: %.S
	$(AS) $(ASFLAGS) -o $@ $<

# Link .o → .elf (using linker script for flat binary layout)
%.elf: %.o flat.ld
	$(LD) $(LDFLAGS) -o $@ $<

# Extract .text + .data → flat .bin
%.bin: %.elf
	$(OBJCOPY) -O binary --only-section=.text --only-section=.data \
		--set-section-flags .bss=alloc,load,contents $< $@
	@echo "Built $@ ($$(wc -c < $@) bytes)"

clean:
	rm -f *.o *.elf *.bin

.PHONY: all clean
