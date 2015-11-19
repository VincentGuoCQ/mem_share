#define VMEM

#include "../common.h"
#include "userspace/errors.h"
#include "userspace/msgfmt.h"

extern struct vmem_dev *Devices;

char * blk_state_str[] = {
	"null",
	"native",
	"mapped",
	NULL,
};
unsigned int state_to_str(struct cli_blk * blk) {
	if(blk->mapped)
	  return 2;
	if(blk->native)
	  return 1;
	return 0;
}

void IP_convert(struct in_addr *ip, unsigned char *str, unsigned int buflen) {
	snprintf(str, buflen, "%d.%d.%d.%d", ((unsigned char *)&(ip->s_addr))[0], ((unsigned char *)&(ip->s_addr))[1], ((unsigned char *)&(ip->s_addr))[2], ((unsigned char *)&(ip->s_addr))[3]);
}

static ssize_t clihost_priser_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char *out = buf;
	struct list_head *p = NULL;
	struct server_host *ps = NULL;
	char IPaddr[IP_ADDR_LEN];

	if(!Devices) {
		return 0;
	}
	
	out += sprintf(out, "Server Name\t\tIP Address\t\t Block Num\n");
	out += sprintf(out, "----------------------------------\n");
	
	mutex_lock(&Devices->lshd_avail_mutex);
	list_for_each(p, &Devices->lshd_available) {
		ps = list_entry(p, struct server_host, ls_available);
		IP_convert(&ps->host_addr, IPaddr, IP_ADDR_LEN);
		out += sprintf(out, "%s\t\t%s\t\t%d\n", ps->host_name, IPaddr, ps->block_num);
	}
	mutex_unlock(&Devices->lshd_avail_mutex);
	return out - buf;
}
static DEVICE_ATTR_RO(clihost_priser);

static ssize_t clihost_priblk_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char *out = buf;
	int nIndex = 0;

	if(!Devices) {
		return 0;
	}
	
	out += sprintf(out, "Block Index\tState\tAddress\n");
	out += sprintf(out, "----------------------------------\n");
	for(nIndex = 0; nIndex < BLK_NUM_MAX; nIndex++) {
		out += sprintf(out, "%d\t\t%s\t", nIndex, blk_state_str[state_to_str(&Devices->addr_entry[nIndex])]);
		out += sprintf(out, "%lx\n", (unsigned long)Devices->addr_entry[nIndex].entry.native.addr);
	}
	return out - buf;
}
	
static DEVICE_ATTR_RO(clihost_priblk);

static ssize_t clihost_op_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgCliOp * cliop = NULL;
	struct server_host *serHost = NULL;
	char IPaddr[IP_ADDR_LEN];
	struct list_head *p = NULL;
	struct server_host *ps = NULL;

	if(count != sizeof(struct MsgCliOp)) {
		printk(KERN_NOTICE"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	cliop = (struct MsgCliOp *)kmalloc(sizeof(struct MsgCliOp), GFP_KERNEL);
	memcpy(cliop, buf, count);
	IP_convert(&cliop->info.addser.host_addr, IPaddr, IP_ADDR_LEN);
	switch(cliop->op) {
		//add server
		case CLIHOST_OP_ADD_SERHOST: {
			printk(KERN_NOTICE"server add\n");
			printk(KERN_NOTICE"name:%s,addr:%s", cliop->info.addser.host_name, IPaddr);
			//allocate memory and copy to memory
			serHost = (struct server_host *)kmem_cache_alloc(Devices->slab_server_host, GFP_KERNEL);
			memset(serHost, 0, sizeof(struct server_host));
			memcpy(serHost->host_name, cliop->info.addser.host_name, HOST_NAME_LEN);
			memcpy(&serHost->host_addr, &cliop->info.addser.host_addr, sizeof(struct in_addr));
			memcpy(&serHost->block_num, &cliop->info.addser.block_num, sizeof(unsigned int));
			//search for existing
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each(p, &Devices->lshd_available) {
				ps = list_entry(p, struct server_host, ls_available);
				if(!memcmp(&ps->host_addr, &serHost->host_addr, sizeof(struct in_addr))) {
					break;
				}
			}
			mutex_unlock(&Devices->lshd_avail_mutex);

			//add to list
			if(p == &Devices->lshd_available) {
				mutex_lock(&Devices->lshd_avail_mutex);
				list_add_tail(&serHost->ls_available, &Devices->lshd_available);
				mutex_unlock(&Devices->lshd_avail_mutex);
			}
			else {
				goto err_ser_exist;
			}
			break;
		}
		//map local memory
		case CLIHOST_OP_MAP_LOCAL:{
			int nCount = 0, nBlk = 0, nIndex = 0;
			printk(KERN_NOTICE"map local\n");
			nBlk = cliop->info.maplocal.block_num;
			printk(KERN_NOTICE"map local num:%d\n", nBlk);
			if(!Devices->addr_entry) {
				goto err_null_ptr;
			}
			for(nIndex = 0; nIndex < BLK_NUM_MAX && nCount < cliop->info.maplocal.block_num; nIndex++) {
				if(FALSE == (Devices->addr_entry[nIndex].mapped)) {
					Devices->addr_entry[nIndex].entry.native.pages = alloc_pages(GFP_USER, BLK_SIZE_SHIFT-PAGE_SHIFT);
					Devices->addr_entry[nIndex].entry.native.addr 
						= kmap(Devices->addr_entry[nIndex].entry.native.pages);
					Devices->addr_entry[nIndex].mapped = TRUE;
					Devices->addr_entry[nIndex].native = TRUE;
					nCount++;
				} 
			}
			break;
		}
	}

	kfree(cliop);
	return count;
err_ser_exist:
	kfree(cliop);
	return ERR_VMEM_HOST_EXIST;
err_null_ptr:
	kfree(cliop);
	return ERR_VMEM_NULL_PTR;
}
static DEVICE_ATTR_WO(clihost_op);

int create_sysfs_file(struct device *dev) {
	int ret = ERR_SUCCESS;
	
	ret = device_create_file(dev, &dev_attr_clihost_priser);
	if (ret) {
		printk(KERN_NOTICE"vmem:create sysfs file error: %d", ret);
		ret = ERR_VMEM_CREATE_FILE;
		goto err_sys_create_clihost_priser;
	}

	ret = device_create_file(dev, &dev_attr_clihost_op);
	if (ret) {
		printk(KERN_NOTICE"vmem:create sysfs file error: %d", ret);
		ret = ERR_VMEM_CREATE_FILE;
		goto err_sys_create_clihost_op;
	}

	ret = device_create_file(dev, &dev_attr_clihost_priblk);
	if (ret) {
		printk(KERN_NOTICE"vmem:create sysfs file error: %d", ret);
		ret = ERR_VMEM_CREATE_FILE;
		goto err_sys_create_clihost_priblk;
	}
	return ret;

err_sys_create_clihost_priblk:
	device_remove_file(dev, &dev_attr_clihost_op);
err_sys_create_clihost_op:
	device_remove_file(dev, &dev_attr_clihost_priser);
err_sys_create_clihost_priser:
	return ret;
}
void delete_sysfs_file(struct device *dev) {
	device_remove_file(dev, &dev_attr_clihost_priser);
	device_remove_file(dev, &dev_attr_clihost_op);
	device_remove_file(dev, &dev_attr_clihost_priblk);
}
