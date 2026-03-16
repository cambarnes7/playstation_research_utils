# MP4 AArch64 EL3 Payload Build
#
# Requires aarch64-linux-gnu-gcc cross-compiler.
# Produces mp4_payload.bin (raw binary) and mp4_payload.h (C hex array).

CROSS_PREFIX ?= aarch64-linux-gnu-

CC      = $(CROSS_PREFIX)gcc
OBJCOPY = $(CROSS_PREFIX)objcopy
XXD     = xxd

CFLAGS  = -nostdlib -fpie -fno-jump-tables -Os -mcpu=cortex-a53 \
          -Wall -Werror -fno-builtin

TARGET  = mp4_payload
SRC     = mp4_payload.c

.PHONY: all clean

all: $(TARGET).bin $(TARGET).h

$(TARGET).o: $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

$(TARGET).bin: $(TARGET).o
	$(OBJCOPY) -O binary -j .text -j .rodata $< $@

# Generate C header with payload as hex array
$(TARGET).h: $(TARGET).bin
	@echo "/* Auto-generated from mp4_payload.bin - DO NOT EDIT */" > $@
	@echo "#ifndef MP4_PAYLOAD_DATA_H" >> $@
	@echo "#define MP4_PAYLOAD_DATA_H" >> $@
	@echo "" >> $@
	@echo "static const unsigned char mp4_payload_bin[] = {" >> $@
	@$(XXD) -i < $< | sed 's/^/    /' >> $@
	@echo "};" >> $@
	@echo "" >> $@
	@echo "static const unsigned int mp4_payload_bin_len = sizeof(mp4_payload_bin);" >> $@
	@echo "" >> $@
	@echo "#endif" >> $@
	@echo "Generated $@ ($(shell wc -c < $<) bytes)"

clean:
	rm -f $(TARGET).o $(TARGET).bin $(TARGET).h
