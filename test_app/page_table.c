#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include "errors.h"
#include "debug.h"
#include "../common.h"
#include "msgfmt.h"
#include "page_table.h"
#include "cmn.h"

extern vpgd_t global_vpgd;
inline void create_vpte(vpde_t * ppde) {
	ppde->vpte_entry = (unsigned long)malloc(sizeof(vpte_t) * (1UL << PTE_SHIFT));
	memset((void *)ppde->vpte_entry, 0, sizeof(vpte_t) * (1UL << PTE_SHIFT));
}
void init_vpde(vpgd_t * ppgd) {
	int nIndex = 0;
	vpde_t *ppde = NULL;
	ppgd->vpde_entry = (unsigned long)malloc(sizeof(vpde_t) * (1UL << PDE_SHIFT));
	ppde = (vpde_t *)ppgd->vpde_entry;
	memset((void *)ppgd->vpde_entry, 0, sizeof(vpde_t) * (1UL << PDE_SHIFT));
//	for(nIndex = 0; nIndex < (1UL << PDE_SHIFT); nIndex++) {
//		 create_vpte(ppde+nIndex);
//	}
	return;
}
inline void destroy_vpte(vpde_t * ppde) {
	int nIndex = 0;
	vpte_t *ppte = (vpte_t *)ppde->vpte_entry;
	for(nIndex = 0; nIndex < (1UL << PTE_SHIFT); nIndex++) {
		if((ppte+nIndex)->vpg_entry) {
			free_page(ppte+nIndex, 1);
		}
	}
	if(ppde->vpte_entry) {
		free((vpte_t *)ppde->vpte_entry);
	}
}
void destroy_vpde(vpgd_t * ppgd) {
	int nIndex = 0;
	vpde_t *ppde = NULL;
	vpte_t *ppte = NULL;
	ppde = (vpde_t *)ppgd->vpde_entry;
	if(!ppde) {
		return;
	}
	for(nIndex = 0; nIndex < (1UL << PDE_SHIFT); nIndex++) {
		if((ppde+nIndex)->vpte_entry) {
			destroy_vpte(ppde + nIndex);
		}
	}
	free(ppde);
	return;
}
void print_vpde(vpgd_t *ppgd) {
	int nIndex = 0, subIndex = 0;
	vpde_t *ppde = NULL;
	vpte_t *ppte = NULL;
	ppde = (vpde_t *)ppgd->vpde_entry;
	printf("addr:%lx val:%lx\n", ppgd, ppgd->vpde_entry);
	if(!ppde) {
		return;
	}
	for(nIndex = 0; nIndex < (1UL << PDE_SHIFT); nIndex++) {
		ppde = ((vpde_t *)ppgd->vpde_entry + nIndex);
		printf("\taddr:%lx val:%lx\n", ppde, ppde->vpte_entry);
		if(ppde->vpte_entry) {
			for(subIndex = 0; subIndex < (1UL << PTE_SHIFT); subIndex++) {
				ppte = ((vpte_t *)ppde->vpte_entry + subIndex);
				printf("\t\taddr:%lx val:%lx attr:%lx\n", ppte, ppte->vpg_entry & VPAGE_MASK,
							ppte->vpg_entry & VOFFSET_MASK);
			}
		}
	}
	return;
}

int read_sysfs_attribute(const char *attr_path, char *buf, unsigned int size) {
	int fd;
	int length;

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		PRINT_INFO("error opening attribute %s\n", attr_path);
		return -1;
	}
	memset(buf, 0, size);
	length = read(fd, buf, size);
	if (length != size) {
		PRINT_INFO("error reading from attribute %s\n", attr_path);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}
int write_sysfs_attribute(const char *attr_path, const char *new_value, size_t len) {
	int fd;
	int length;

	fd = open(attr_path, O_WRONLY | O_SYNC);
	if (fd < 0) {
		PRINT_INFO("error opening attribute %s\n", attr_path);
		return -1;
	}
	length = write(fd, new_value, len);
	if (length < 0) {
		PRINT_INFO("error writing to attribute %s\n", attr_path);
	}
	close(fd);
	return length;
}
int alloc_page(vpte_t *ppte, unsigned int pagenum) {
	int i = 0;
	struct MsgMemAlloc memalloc;
	struct MsgMemRet memret;
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	memset(path, 0, SYSFS_PATH_MAX);
	memset(&memalloc, 0, sizeof(struct MsgMemAlloc));
	memset(&memret, 0, sizeof(struct MsgMemRet));

	if(0 == pagenum) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	memalloc.vpagenum = pagenum;
	
	//write to file and read from file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_ALLOC_PATH);
	write_sysfs_attribute(path, (char *)&memalloc, sizeof(struct MsgMemAlloc));
	read_sysfs_attribute(path, (char *)&memret, sizeof(struct MsgMemRet));
	for(i = 0; i < memret.vpagenum; i++) {
		 (ppte+i)->vpg_entry = memret.vpageaddr[i];
		 (ppte+i)->vpg_entry |= PG_PRESENT;
	}
err_args:
	return ret;
}
int vread(void *buf, unsigned long addr, unsigned long count) {
	unsigned long firpage = 0, pagecount = 0;
	unsigned long nIndex = 0;
	vpde_t *ppde = (vpde_t *)global_vpgd.vpde_entry;
	vpte_t *ppte = NULL;
	firpage = ADDR_TO_PAGE_INDEX(addr);
	pagecount = (((count+(addr & VOFFSET_MASK)-1) & VPAGE_MASK) >> VPAGE_SIZE_SHIFT)+1;
	printf("firpage:%d, pagecount:%d\n", firpage, pagecount);
	if(!(ppde+PAGE_TO_PDE(firpage))->vpte_entry) {
		create_vpte(ppde+PAGE_TO_PDE(firpage));
	}
	ppte =(vpte_t *)((ppde+PAGE_TO_PDE(firpage))->vpte_entry); 
	if(!(ppte+PAGE_TO_PTE(firpage))->vpg_entry) {
		alloc_page(ppte+PAGE_TO_PTE(firpage), 1);
	}
	if(pagecount > 1) {
		for(nIndex = firpage+1; nIndex < firpage+pagecount-1; nIndex++) {
			if(!(ppde+PAGE_TO_PDE(nIndex))->vpte_entry) {
				create_vpte(ppde+PAGE_TO_PDE(nIndex));
			}
			ppte =(vpte_t *)((ppde+PAGE_TO_PDE(nIndex))->vpte_entry); 
			if(!(ppte+PAGE_TO_PTE(nIndex))->vpg_entry) {
				alloc_page(ppte+PAGE_TO_PTE(nIndex), 1);
			}
		}
	
		if(!(ppde+PAGE_TO_PDE(firpage+pagecount-1))->vpte_entry) {
			create_vpte(ppde+PAGE_TO_PDE(firpage+pagecount-1));
		}
		ppte =(vpte_t *)((ppde+PAGE_TO_PDE(firpage+pagecount-1))->vpte_entry); 
		if(!(ppte+PAGE_TO_PTE(firpage+pagecount-1))->vpg_entry) {
			alloc_page(ppte+PAGE_TO_PTE(firpage+pagecount-1), 1);
		}
	}
	return 0;
}

int vwrite(void *buf, unsigned long addr, unsigned long count) {
	return 0;
}
int free_page(vpte_t *ppte, unsigned int pagenum) {
	int i = 0;
	struct MsgMemFree memfree;
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	memset(path, 0, SYSFS_PATH_MAX);
	memset(&memfree, 0, sizeof(struct MsgMemAlloc));

	if(0 == pagenum || pagenum > VPAGE_PER_FREE) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	memfree.vpagenum = pagenum;
	
	for(i = 0; i < pagenum ; i++) {
		 memfree.vpageaddr[i] = (ppte+i)->vpg_entry & ~((1UL << VPAGE_SIZE_SHIFT)-1);
		 (ppte+i)->vpg_entry = 0;
	}
	//write to file and read from file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_FREE_PATH);
	write_sysfs_attribute(path, (char *)&memfree, sizeof(struct MsgMemFree));
err_args:
	return ret;
}
int vmem_write_page() {
	int fd;
	int length;
	off_t off;
	int opt = 0, nIndex = 0;
	char buf[VPAGE_SIZE];
	char *pageaddr = NULL, *data = NULL;

	memset(buf, 0, VPAGE_SIZE);
	if(NULL == pageaddr || NULL == data) {
		return -1;
	}

	if((off = strtol(pageaddr, NULL, 16)) < 0) {
		return -1;
	}
	memcpy(buf, data, strlen(data));
	fd = open("/dev/vmem", O_WRONLY);
	if (fd < 0) {
		printf("error opening attribute vmem\n");
		return -1;
	}
	length = pwrite(fd, buf, VPAGE_SIZE, off);
	if (length != VPAGE_SIZE) {
		printf("error writing to file, length = %d\n", length);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int vmem_read_page() {
	int fd;
	int length;
	off_t off;
	int opt = 0, nIndex = 0;
	char *pageaddr = NULL;
	char data[VPAGE_SIZE];

	memset(data, 0, VPAGE_SIZE);
	if(NULL == pageaddr) {
		return -1;
	}

	if((off = strtol(pageaddr, NULL, 16)) < 0) {
		return -1;
	}
	fd = open("/dev/vmem", O_RDONLY);
	if (fd < 0) {
		printf("error opening attribute vmem\n");
		return -1;
	}
	length = pread(fd, data, VPAGE_SIZE, off);
	if (length <= 0) {
		printf("error writing to file, length = %d\n", length);
		close(fd);
		return -1;
	}
	printf("%s\n",data);
	close(fd);
	return 0;
}
