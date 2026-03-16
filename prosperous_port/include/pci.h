#ifndef PROSPEROUS_PCI_H
#define PROSPEROUS_PCI_H

#include <stdint.h>

#define MMCFG_BASE 0xF0000000ULL

static inline uint64_t pci_cfg_addr(uint32_t bus, uint32_t device, uint32_t function, uint32_t offset)
{
    return MMCFG_BASE | ((uint64_t)bus << 20) | ((uint64_t)device << 15) |
           ((uint64_t)function << 12) | offset;
}

#define PCI_B0D0F0      pci_cfg_addr(0, 0, 0, 0)
#define PCI_B0D18F2     pci_cfg_addr(0, 0x18, 2, 0)
#define PCI_B0D18F4     pci_cfg_addr(0, 0x18, 4, 0)

#endif
