CC      := gcc
OBJCOPY := objcopy
ODIR    := build
SDIR    := src

CFLAGS  := -Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin \
           -nostartfiles -nostdlib -Wall -march=btver2 -mtune=btver2 \
           -m64 -mabi=sysv -mcmodel=small -fpie -fno-stack-protector

LFLAGS  := -Xlinker -T ./linker.x -Wl,--build-id=none -Wl,--gc-sections -nostdlib

TARGET  := gadget_reader.bin
ELF     := gadget_reader.elf

PSRC_TARGET := pivot_scan.bin
PSRC_ELF    := pivot_scan.elf

.PHONY: all clean pivot_scan

all: $(TARGET)

pivot_scan: $(PSRC_TARGET)

$(TARGET): $(ODIR) $(ODIR)/main.o
	$(CC) $(ODIR)/main.o -o $(ELF) $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ELF) $(TARGET)
	mv $(ELF) $(ODIR)/

$(PSRC_TARGET): $(ODIR) $(ODIR)/pivot_scan.o
	$(CC) $(ODIR)/pivot_scan.o -o $(PSRC_ELF) $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(PSRC_ELF) $(PSRC_TARGET)
	mv $(PSRC_ELF) $(ODIR)/

$(ODIR)/main.o: $(SDIR)/main.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/pivot_scan.o: $(SDIR)/pivot_scan.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir -p $(ODIR)

clean:
	rm -rf $(TARGET) $(PSRC_TARGET) $(ODIR)
