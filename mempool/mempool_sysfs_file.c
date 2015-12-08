#include "../include.h"
#include "../common.h"
#include "../kererr.h"
#include "mempool_common.h"
#include "userspace/errors.h"
#include "userspace/msgfmt.h"

extern struct mempool_dev *Devices;

char * blk_state_str[] = {
	"null",
	"available",
	"in use",
	NULL,
};

unsigned int blk_state_to_str(struct mempool_blk * blk) {
	if(blk->inuse)
	  return 2;
	if(blk->avail)
	  return 1;
	return 0;
}
char * clihost_state_str[] = {
	"connected",
	NULL,
};
unsigned int clihost_state_to_str(struct client_host * clihost) {
	if(clihost->state == CLIHOST_STATE_CONNECTED)
	  return 1;
	return 0;
}
void IP_convert(struct in_addr *ip, unsigned char *str, unsigned int buflen) {
	snprintf(str, buflen, "%d.%d.%d.%d", ((unsigned char *)&(ip->s_addr))[0], ((unsigned char *)&(ip->s_addr))[1], ((unsigned char *)&(ip->s_addr))[2], ((unsigned char *)&(ip->s_addr))[3]);
}

static ssize_t clihost_state_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char *out = buf;
	struct list_head *p = NULL;
	struct client_host *clihost = NULL;
	char IPaddr[IP_ADDR_LEN];

	if(!Devices) {
		return 0;
	}
	
	out += sprintf(out, "Client Name\tIP Address\tBlock In Use\tState\n");
	out += sprintf(out, "--------------------------------------------\n");
	
	mutex_lock(&Devices->lshd_rent_client_mutex);
	list_for_each(p, &Devices->lshd_rent_client) {
		clihost = list_entry(p, struct client_host, ls_rent);
		IP_convert(&clihost->host_addr.sin_addr, IPaddr, IP_ADDR_LEN);
		out += sprintf(out, "%s\t\t%s\t%d\t", clihost->host_name, IPaddr, clihost->block_num);
		out += sprintf(out, "%s\n", clihost_state_str[clihost_state_to_str(clihost)]);
	}
	mutex_unlock(&Devices->lshd_rent_client_mutex);
	return out - buf;
}
static DEVICE_ATTR_RO(clihost_state);

static ssize_t blk_state_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char *out = buf;
	int nIndex = 0;
	if(!Devices) {
		return 0;
	}

	out += sprintf(out, "Block Index\t\tState\t\tAddress\t\tSize\n");
	out += sprintf(out, "----------------------------------\n");
	for(nIndex = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL; nIndex++) {
		out += sprintf(out, "%d\t", nIndex);
		out += sprintf(out, "%s\t\t", blk_state_str[blk_state_to_str(&(Devices->blk[nIndex]))]);
		out += sprintf(out, "%lx\t%ld\n", (unsigned long)Devices->blk[nIndex].blk_addr, BLK_SIZE);
	}
	return out - buf;
}
static DEVICE_ATTR_RO(blk_state);

static ssize_t serhost_cfg_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgSerOp * serop = NULL;

	if(count != sizeof(struct MsgSerOp)) {
		KER_DEBUG(KERN_NOTICE"mempool:%s:illegal input\n", __FUNCTION__);
		return 0;
	}

	serop = (struct MsgSerOp *)kmalloc(sizeof(struct MsgSerOp), GFP_KERNEL);
	memcpy(serop, buf, count);
	switch(serop->op) {
		int nCount = 0;
		unsigned int nIndex = 0;
		//add available block
		case SERHOST_OP_ADD_BLK:
			KER_DEBUG(KERN_NOTICE"mempool:add block called\n");
			for(nIndex = 0, nCount = 0; (nIndex < MAX_BLK_NUM_IN_MEMPOOL) && (nCount < serop->info.addblk.block_num); nIndex++) {
				if(!Devices->blk[nIndex].avail) {
					Devices->blk[nIndex].blk_pages = alloc_pages(GFP_USER, BLK_SIZE_SHIFT-PAGE_SHIFT);
					Devices->blk[nIndex].blk_addr = kmap(Devices->blk[nIndex].blk_pages);
					Devices->blk[nIndex].avail = TRUE;
					nCount++;
				}
			}
			break;
	}

	kfree(serop);
	return count;
}
static DEVICE_ATTR_WO(serhost_cfg);

int create_sysfs_file(struct device *dev) {
	int ret = KERERR_SUCCESS;
	if(!dev) {
		ret = KERERR_NULL_PTR;
		goto err_null_ptr;
	}
	ret = device_create_file(dev, &dev_attr_clihost_state);
	if (ret) {
		KER_DEBUG(KERN_NOTICE"mempool:create sysfs file clihost_state error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_state;
	}

	ret = device_create_file(dev, &dev_attr_serhost_cfg);
	if (ret) {
		KER_DEBUG(KERN_NOTICE"mempool:create sysfs file serhost_cfg error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_serhost_cfg;
	}

	ret = device_create_file(dev, &dev_attr_blk_state);
	if (ret) {
		KER_DEBUG(KERN_NOTICE"mempool:create sysfs file blk_state error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_blk_state;
	}
	return ret;
err_sys_create_blk_state:
	device_create_file(dev, &dev_attr_serhost_cfg);
err_sys_create_serhost_cfg:
	device_create_file(dev, &dev_attr_clihost_state);
err_sys_create_clihost_state:
err_null_ptr:
	return ret;
}
void delete_sysfs_file(struct device *dev) {
	device_remove_file(dev, &dev_attr_clihost_state);
	device_remove_file(dev, &dev_attr_serhost_cfg);
	device_remove_file(dev, &dev_attr_blk_state);
}
