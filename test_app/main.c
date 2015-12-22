#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "page_table.h"

vpgd_t global_vpgd = { 0 };

void main() {
	vpde_t *ppde = NULL;
	vpte_t *ppte = NULL;
	init_vpde(&global_vpgd);
	ppde = (vpde_t *)global_vpgd.vpde_entry;
	ppte = (vpte_t *)ppde->vpte_entry;
	vread(NULL, 0x3800, 0xC11);
	//vread(NULL, 0x805, 0x34);
	//vread(NULL, 0xc53, 0x24);
	//alloc_page(ppte, 2);
	print_vpde(&global_vpgd);
	//free_page(ppte, 2);
	destroy_vpde(&global_vpgd);
	return;
}
