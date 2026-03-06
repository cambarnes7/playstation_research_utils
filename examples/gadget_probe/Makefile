CC      := gcc
OBJCOPY := objcopy
ODIR    := build
SDIR    := src

CFLAGS  := -Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin \
           -nostartfiles -nostdlib -Wall -march=btver2 -mtune=btver2 \
           -m64 -mabi=sysv -mcmodel=small -fpie -fno-stack-protector

LFLAGS  := -Xlinker -T ./linker.x -Wl,--build-id=none -Wl,--gc-sections -nostdlib

# Override from command line: make TARGET_OFFSET=-0x9cf991 PROBE_MODE=0
PROBE_MODE    ?= 0
TARGET_OFFSET ?= -0x9cf991

TARGET  := gadget_probe.bin
ELF     := gadget_probe.elf

$(TARGET): $(ODIR) $(ODIR)/main.o
	$(CC) $(ODIR)/main.o -o $(ELF) $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ELF) $(TARGET)
	mv $(ELF) $(ODIR)/

$(ODIR)/main.o: $(SDIR)/main.c
	$(CC) -c -o $@ $< $(CFLAGS) \
		-DPROBE_MODE=$(PROBE_MODE) \
		-DTARGET_OFFSET='($(TARGET_OFFSET))'

$(ODIR):
	@mkdir -p $(ODIR)

.PHONY: clean
clean:
	rm -rf $(TARGET) $(ODIR)
