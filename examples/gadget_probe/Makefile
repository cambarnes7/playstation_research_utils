CC      := gcc
OBJCOPY := objcopy
ODIR    := build
SDIR    := src

CFLAGS  := -Os -std=c11 -ffunction-sections -fdata-sections -fno-builtin \
           -nostartfiles -nostdlib -Wall -march=btver2 -mtune=btver2 \
           -m64 -mabi=sysv -mcmodel=small -fpie -fno-stack-protector \
           -mno-red-zone

LFLAGS  := -Xlinker -T ./linker.x -Wl,--build-id=none -Wl,--gc-sections -nostdlib

# Override from command line: make TARGET_OFFSET=-0x9cf991 PROBE_MODE=0
PROBE_MODE    ?= 0
TARGET_OFFSET ?= -0x9cf991

# Smart pivot scanner parameters
SCAN_BATCH  ?= 0
BATCH_SIZE  ?= 8
PROBE_DEPTH ?= 128

# Kdata harvester parameters
SCAN_CHUNK  ?= 0
CHUNK_SIZE  ?= 0x100000

TARGET  := gadget_probe.bin
ELF     := gadget_probe.elf

.PHONY: all clean smart_pivot kdata_harvest batch_pivot ktext_map apic_dump

all: $(TARGET)

$(TARGET): $(ODIR) $(ODIR)/main.o
	$(CC) $(ODIR)/main.o -o $(ELF) $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ELF) $(TARGET)
	mv $(ELF) $(ODIR)/

$(ODIR)/main.o: $(SDIR)/main.c
	$(CC) -c -o $@ $< $(CFLAGS) \
		-DPROBE_MODE=$(PROBE_MODE) \
		-DTARGET_OFFSET='($(TARGET_OFFSET))'

# Smart pivot scanner: danger-zone-aware ktext probing
smart_pivot: $(ODIR) $(ODIR)/smart_pivot_scan.o
	$(CC) $(ODIR)/smart_pivot_scan.o -o $(ODIR)/smart_pivot_scan.elf $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ODIR)/smart_pivot_scan.elf smart_pivot_scan.bin

$(ODIR)/smart_pivot_scan.o: $(SDIR)/smart_pivot_scan.c
	$(CC) -c -o $@ $< $(CFLAGS) \
		-DSCAN_BATCH=$(SCAN_BATCH) \
		-DBATCH_SIZE=$(BATCH_SIZE) \
		-DPROBE_DEPTH=$(PROBE_DEPTH)

# Kdata pointer harvester: scan kdata for ktext function pointers
kdata_harvest: $(ODIR) $(ODIR)/kdata_harvester.o
	$(CC) $(ODIR)/kdata_harvester.o -o $(ODIR)/kdata_harvester.elf $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ODIR)/kdata_harvester.elf kdata_harvester.bin

$(ODIR)/kdata_harvester.o: $(SDIR)/kdata_harvester.c
	$(CC) -c -o $@ $< $(CFLAGS) \
		-DSCAN_CHUNK=$(SCAN_CHUNK) \
		-DCHUNK_SIZE=$(CHUNK_SIZE)

# Batch pivot scanner (original)
batch_pivot: $(ODIR) $(ODIR)/batch_pivot_scan.o
	$(CC) $(ODIR)/batch_pivot_scan.o -o $(ODIR)/batch_pivot_scan.elf $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ODIR)/batch_pivot_scan.elf batch_pivot_scan.bin

$(ODIR)/batch_pivot_scan.o: $(SDIR)/batch_pivot_scan.c
	$(CC) -c -o $@ $< $(CFLAGS)

# Ktext mapper
ktext_map: $(ODIR) $(ODIR)/ktext_mapper.o
	$(CC) $(ODIR)/ktext_mapper.o -o $(ODIR)/ktext_mapper.elf $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ODIR)/ktext_mapper.elf ktext_mapper.bin

$(ODIR)/ktext_mapper.o: $(SDIR)/ktext_mapper.c
	$(CC) -c -o $@ $< $(CFLAGS)

# APIC ops dump
apic_dump: $(ODIR) $(ODIR)/apic_dump.o
	$(CC) $(ODIR)/apic_dump.o -o $(ODIR)/apic_dump.elf $(CFLAGS) $(LFLAGS)
	$(OBJCOPY) -S -O binary $(ODIR)/apic_dump.elf apic_dump.bin

$(ODIR)/apic_dump.o: $(SDIR)/apic_dump.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir -p $(ODIR)

clean:
	rm -rf $(ODIR) *.bin
