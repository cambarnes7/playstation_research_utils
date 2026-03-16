#ifndef PROSPEROUS_TMR_H
#define PROSPEROUS_TMR_H

#include <stdint.h>
#include "pci.h"

/*
 * AMD Trusted Memory Region (TMR) access.
 *
 * TMRs are configured via indirect registers on PCI B0:D18:F2.
 * Index register at +0x80, data register at +0x84.
 *
 * Each TMR entry is 0x10 bytes:
 *   +0x00: base (physical address >> 16)
 *   +0x04: limit (physical address >> 16)
 *   +0x08: cfg (control flags)
 *   +0x0C: requestors (access control)
 *
 * cfg value 0x3f07 = all requestors allowed, TMR enabled
 * cfg value 0x0000 = TMR disabled
 *
 * Key TMR indices on PS5:
 *   TMR 5:  HV protection (master)
 *   TMR 16: Kernel text / HV text+data
 *   TMR 17: HV region protection
 *   TMR 18: HV region protection
 *   TMR 19: PSP carveout
 *   TMR 20: MP4 carveout (0x60000000:0x605f0000)
 *   TMR 21: Available for our use (user-defined)
 *
 * IMPORTANT: TMR manipulation stops working at FW >= 5.00
 *            because TMR becomes non-modifiable by x86.
 */

#define TMR_IND_INDEX_OFF   0x80
#define TMR_IND_DATA_OFF    0x84

struct tmr_entry {
    uint32_t base;
    uint32_t limit;
    uint32_t cfg;
    uint32_t requestors;
};

struct tmr_access {
    uint64_t dmap_base;
    uint64_t ind_index_pa;
    uint64_t ind_data_pa;
};

/* TMR cfg flags */
#define TMR_CFG_ALL_ACCESS  0x3f07
#define TMR_CFG_DISABLED    0x0000

static inline void tmr_init(struct tmr_access *tmr, uint64_t dmap_base)
{
    tmr->dmap_base = dmap_base;
    tmr->ind_index_pa = PCI_B0D18F2 + TMR_IND_INDEX_OFF;
    tmr->ind_data_pa = PCI_B0D18F2 + TMR_IND_DATA_OFF;
}

#endif
