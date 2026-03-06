CC      := gcc
OBJCOPY := objcopy
ODIR    := build
SDIR    := src

CFLAGS  := -Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin \
           -nostartfiles -nostdlib -Wall -march=btver2 -mtune=btver2 \
           -m64 -mabi=sysv -mcmodel=small -fpie -fno-stack-protector \
           -mno-red-zone

LFLAGS  := -Xlinker -T ./linker.x -Wl,--build-id=none -Wl,--gc-sections -nostdlib

TARGET  := pcb_onfault_test.bin
ELF     := pcb_onfault_test.elf

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(ODIR) $(ODIR)/main.o
	$(CC) $(ODIR)/main.o -o $(ELF) $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ELF) $(TARGET)
	mv $(ELF) $(ODIR)/

$(ODIR)/main.o: $(SDIR)/main.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir -p $(ODIR)

clean:
	rm -rf $(ODIR) *.bin
