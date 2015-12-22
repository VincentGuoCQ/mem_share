#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H
#include "../common.h"

typedef struct {unsigned long vpte_entry;} vpde_t;
typedef struct {unsigned long vpg_entry;} vpte_t;
typedef struct {unsigned long vpde_entry;} vpgd_t;

#define PTE_SHIFT	3
#define PDE_SHIFT	3

#define PG_PRESENT (1UL << 9)
#define PG_WR (1UL << 8)
#define PG_RD (1UL << 7)
#define PG_EXCUTE (1UL << 6)

void init_vpde(vpgd_t * ppgd);
void destroy_vpde(vpgd_t * ppgd);
void print_vpde(vpgd_t *ppgd);
#define VOFFSET_MASK ((1UL << VPAGE_SIZE_SHIFT)-1)
#define VPAGE_MASK (~((1UL << VPAGE_SIZE_SHIFT)-1))
#define ADDR_TO_PAGE_INDEX(ADDR)	((ADDR >> VPAGE_SIZE_SHIFT) & ((1UL <<(PTE_SHIFT+PDE_SHIFT))-1))
#define PAGE_TO_PDE(PAGE) ((PAGE >> PTE_SHIFT) & ((1UL <<PDE_SHIFT)-1))
#define PAGE_TO_PTE(PAGE) (PAGE & ((1UL <<PTE_SHIFT)-1))

#endif //PAGE_TABLE_H
