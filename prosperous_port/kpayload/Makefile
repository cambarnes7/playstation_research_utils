# Kernel RPC Payload Build
#
# Build with host g++ targeting PS5's AMD Zen 2 CPU.
# Produces kpayload (raw binary) loaded into kernel memory.

CXX     = g++
OBJCOPY = objcopy

CXXFLAGS = -Wall -Wno-unused-function -Werror -pie -Os -g \
           -masm=intel -march=znver2 \
           -fcf-protection=none -fno-exceptions -fno-rtti \
           -nostdlib -ffreestanding -static \
           -ffunction-sections -Wl,--gc-sections -Wl,--build-id=none

TARGET  = kpayload
SRC     = kpayload.cpp
LD_SCRIPT = kpayload.ld

.PHONY: all clean

all: $(TARGET)

$(TARGET).elf: $(SRC) $(LD_SCRIPT)
	$(CXX) $(CXXFLAGS) -o $@ $< -T $(LD_SCRIPT)

$(TARGET): $(TARGET).elf
	$(OBJCOPY) -O binary $< $@
	@echo "Payload size: $$(wc -c < $@) bytes (max 16384)"
	@test $$(wc -c < $@) -le 16384 || (echo "ERROR: Payload too large!" && rm $@ && false)

clean:
	rm -f $(TARGET).elf $(TARGET)
