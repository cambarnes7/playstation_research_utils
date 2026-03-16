#ifndef PROSPEROUS_SMN_H
#define PROSPEROUS_SMN_H

#include <stdint.h>
#include "pci.h"

/*
 * AMD System Management Network (SMN) access via PCI config space.
 * SMN index/data registers are at B0:D0:F0 offset 0x60/0x64.
 * On PS5 (Aeolia/Belize), the SMN address space gives access to
 * IOMMU registers, NB resources, and other SoC peripherals.
 */

#define SMN_INDEX_OFFSET    0x60
#define SMN_DATA_OFFSET     0x64

/* Alternative SMN access pair at 0xA0/0xA4 (used by kpayload) */
#define SMN_INDEX2_OFFSET   0xA0
#define SMN_DATA2_OFFSET    0xA4

/* IOMMU base in SMN address space */
#define SMN_IOMMU_BASE      0x02400000

/* SMN access functions - require DMAP-based physical memory R/W */
struct smn_access {
    uint64_t dmap_base;
    uint64_t index_pa;
    uint64_t data_pa;
};

static inline void smn_init(struct smn_access *smn, uint64_t dmap_base)
{
    smn->dmap_base = dmap_base;
    smn->index_pa = PCI_B0D0F0 + SMN_INDEX_OFFSET;
    smn->data_pa = PCI_B0D0F0 + SMN_DATA_OFFSET;
}

#endif
