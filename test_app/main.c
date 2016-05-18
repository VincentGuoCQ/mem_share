#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common.h"
#include "page_table.h"

vpgd_t global_vpgd = { 0 };
struct list_head global_page_list;

void main() {
	vpde_t *ppde = NULL;
	vpte_t *ppte = NULL;
	unsigned long addr = 0;
	int i = 0;
	init_vpde(&global_vpgd);
	list_init(&global_page_list);
	ppde = (vpde_t *)global_vpgd.vpde_entry;
	ppte = (vpte_t *)ppde->vpte_entry;
	srand((unsigned)time(NULL));
	for(i = 0; ; i++) {
		addr = rand() % (3 *(1UL << (PTE_SHIFT + VPAGE_SIZE_SHIFT)));
		vread(NULL, addr, 0x1);
		//sleep(1);
		if('#' == getchar())
		  break;
	}
	//alloc_page(ppte, 2);
	print_vpde(&global_vpgd);
	//free_page(ppte, 2);
	destroy_vpde(&global_vpgd);
	return;
}
