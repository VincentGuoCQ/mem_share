#define VMEM

#include "../common.h"
#include "userspace/errors.h"
#include "userspace/msgfmt.h"
#include "../net_msg.h"

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

	out += sprintf(out, "Server Name\t\tIP Address\t\t Block Num\t\tState\n");
	out += sprintf(out, "----------------------------------\n");

	mutex_lock(&Devices->lshd_avail_mutex);
	list_for_each(p, &Devices->lshd_available) {
		ps = list_entry(p, struct server_host, ls_available);
		IP_convert(&ps->host_addr.sin_addr, IPaddr, IP_ADDR_LEN);
		out += sprintf(out, "%s\t\t%s\t\t%d\t\tavailable\n",
					ps->host_name, IPaddr, ps->block_available);
	}
	mutex_unlock(&Devices->lshd_avail_mutex);
	mutex_lock(&Devices->lshd_inuse_mutex);
	list_for_each(p, &Devices->lshd_inuse) {
		ps = list_entry(p, struct server_host, ls_inuse);
		IP_convert(&ps->host_addr.sin_addr, IPaddr, IP_ADDR_LEN);
		out += sprintf(out, "%s\t\t%s\t\t%d\t\tinuse\n",
					ps->host_name, IPaddr, ps->block_available);
	}
	mutex_unlock(&Devices->lshd_inuse_mutex);
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
		mutex_lock(&Devices->addr_entry[nIndex].handle_mutex);
		out += sprintf(out, "%d\t\t%s\t", nIndex, blk_state_str[state_to_str(&Devices->addr_entry[nIndex])]);
		out += sprintf(out, "%lx\n", (unsigned long)Devices->addr_entry[nIndex].entry.native.addr);
		mutex_unlock(&Devices->addr_entry[nIndex].handle_mutex);
	}
	return out - buf;
}
	
static DEVICE_ATTR_RO(clihost_priblk);

static ssize_t clihost_op_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgCliOp * cliop = NULL;
	struct server_host *serhost = NULL;
	struct list_head *p = NULL, *next = NULL;
	char IPaddr[IP_ADDR_LEN];

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
			printk(KERN_NOTICE"vmem:server add\n");
			printk(KERN_NOTICE"name:%s,addr:%s", cliop->info.addser.host_name, IPaddr);
			//allocate memory and copy to memory
			serhost = (struct server_host *)kmem_cache_alloc(Devices->slab_server_host, GFP_KERNEL);
			memset(serhost, 0, sizeof(struct server_host));
			memcpy(serhost->host_name, cliop->info.addser.host_name, HOST_NAME_LEN);
			memcpy(&serhost->host_addr.sin_addr, &cliop->info.addser.host_addr, sizeof(struct in_addr));
			memcpy(&serhost->block_available, &cliop->info.addser.block_num, sizeof(unsigned int));
			//search for existing
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each(p, &Devices->lshd_available) {
				serhost = list_entry(p, struct server_host, ls_available);
				if(!memcmp(&serhost->host_addr, &serhost->host_addr, sizeof(struct in_addr))) {
					break;
				}
			}
			mutex_unlock(&Devices->lshd_avail_mutex);

			//add to list
			if(p == &Devices->lshd_available) {
				mutex_init(&serhost->ptr_mutex);
				mutex_init(&serhost->lshd_req_msg_mutex);
				mutex_init(&serhost->lshd_rpy_msg_mutex);
				INIT_LIST_HEAD(&serhost->lshd_req_msg);
				INIT_LIST_HEAD(&serhost->lshd_rpy_msg);
				serhost->slab_netmsg_req = Devices->slab_netmsg_req;
				serhost->slab_netmsg_rpy = Devices->slab_netmsg_rpy;
				mutex_lock(&Devices->lshd_avail_mutex);
				list_add_tail(&serhost->ls_available, &Devices->lshd_available);
				mutex_unlock(&Devices->lshd_avail_mutex);

			}
			else {
				kmem_cache_free(Devices->slab_server_host, serhost);
				goto err_ser_exist;
			}
			break;
		}
		//map local memory
		case CLIHOST_OP_MAP_LOCAL:{
			int nCount = 0, nBlk = 0, nIndex = 0;
			printk(KERN_NOTICE"vmem:map local\n");
			nBlk = cliop->info.maplocal.block_num;
			printk(KERN_NOTICE"vmem:map local num:%d\n", nBlk);
			if(!Devices->addr_entry) {
				goto err_null_ptr;
			}
			for(nIndex = 0; nIndex < BLK_NUM_MAX && 
						nCount < cliop->info.maplocal.block_num; nIndex++) {
				if(FALSE == (Devices->addr_entry[nIndex].mapped)) {
					mutex_lock(&Devices->addr_entry[nIndex].handle_mutex);
					Devices->addr_entry[nIndex].entry.native.pages =
						alloc_pages(GFP_USER, BLK_SIZE_SHIFT-PAGE_SHIFT);
					Devices->addr_entry[nIndex].entry.native.addr 
						= kmap(Devices->addr_entry[nIndex].entry.native.pages);
					Devices->addr_entry[nIndex].mapped = TRUE;
					Devices->addr_entry[nIndex].native = TRUE;
					mutex_unlock(&Devices->addr_entry[nIndex].handle_mutex);
					nCount++;
				} 
			}
			break;
		}
		case CLIHOST_OP_DEL_SERHOST_AVAIL: {
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each_safe(p, next, &Devices->lshd_available) {
				serhost = list_entry(p, struct server_host, ls_available);
				list_del(&serhost->ls_available);
				kmem_cache_free(Devices->slab_server_host, serhost);
			}
			mutex_unlock(&Devices->lshd_avail_mutex);
			printk(KERN_INFO"vmem:delete serverhost avail list\n");
			break;
		}
		case CLIHOST_OP_DEL_SERHOST_INUSE: {
			mutex_lock(&Devices->lshd_inuse_mutex);
			list_for_each_safe(p, next, &Devices->lshd_inuse) {
				struct list_head *sp = NULL, *snext = NULL;
				struct netmsg_req *netmsg_req = NULL;
				serhost = list_entry(p, struct server_host, ls_inuse);

				mutex_lock(&serhost->lshd_req_msg_mutex);
				list_for_each_safe(sp, snext, &serhost->lshd_req_msg) {
					netmsg_req = list_entry(sp, struct netmsg_req, ls_reqmsg);
					list_del(&netmsg_req->ls_reqmsg);
					kmem_cache_free(serhost->slab_netmsg_req, netmsg_req);
				}
				mutex_unlock(&serhost->lshd_req_msg_mutex);
				printk(KERN_INFO"vmem:delete serverhost netmsg req\n");

				mutex_lock(&serhost->ptr_mutex);
				if(serhost->sock) {
					sock_release(serhost->sock);
					serhost->sock = NULL;
				}
				mutex_unlock(&serhost->ptr_mutex);
				printk(KERN_INFO"vmem:delete serverhost inuse sock\n");
				if(serhost->SerSendThread) {
					kthread_stop(serhost->SerSendThread);
					serhost->SerSendThread = NULL;
				}
				printk(KERN_INFO"vmem:delete serverhost inuse send thread\n");

				list_del(&serhost->ls_inuse);
				kmem_cache_free(Devices->slab_server_host, serhost);
			}
			mutex_unlock(&Devices->lshd_inuse_mutex);
			printk(KERN_INFO"vmem:delete serverhost inuse list\n");
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

static ssize_t clihost_memctrl_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgMemCtrl * memctrl = NULL;

	if(count != sizeof(struct MsgMemCtrl)) {
		printk(KERN_NOTICE"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	memctrl = (struct MsgMemCtrl *)kmalloc(sizeof(struct MsgMemCtrl), GFP_KERNEL);
	memcpy(memctrl, buf, count);
	switch(memctrl->ctrlId) {
		//alloc page
		case CLIHOST_MEMCTRL_ALLOC_PAGE: {
			unsigned int nIndex = 0;
			unsigned int nCount = 0;

			for(nIndex = 0; nIndex < BLK_NUM_MAX
						&& nCount < memctrl->info.allocpage.pagenum; nIndex++) {
				mutex_lock(&Devices->addr_entry[nIndex].handle_mutex);
				if(Devices->addr_entry[nIndex].mapped
						&& Devices->addr_entry[nIndex].inuse_count < VPAGE_NUM_IN_BLK) {
					Devices->addr_entry[nIndex].inuse_count++;
					nCount++;
				}
				mutex_unlock(&Devices->addr_entry[nIndex].handle_mutex);
			}

			break;
		}
		//free page
		case CLIHOST_MEMCTRL_FREE_PAGE: {
			unsigned int nIndex = 0;
			unsigned int nCount = 0;

			for(nIndex = 0; nIndex < BLK_NUM_MAX
						&& nCount < memctrl->info.allocpage.pagenum; nIndex++) {
				mutex_lock(&Devices->addr_entry[nIndex].handle_mutex);
				if(Devices->addr_entry[nIndex].mapped
						&& Devices->addr_entry[nIndex].inuse_count > 0) {
					Devices->addr_entry[nIndex].inuse_count--;
					nCount++;
				}
				mutex_unlock(&Devices->addr_entry[nIndex].handle_mutex);
			}
			break;
		}
	}
	kfree(memctrl);
	return count;
}
static DEVICE_ATTR_WO(clihost_memctrl);

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

	ret = device_create_file(dev, &dev_attr_clihost_memctrl);
	if (ret) {
		printk(KERN_NOTICE"vmem:create sysfs file error: %d", ret);
		ret = ERR_VMEM_CREATE_FILE;
		goto err_sys_create_clihost_memctrl;
	}
	return ret;
err_sys_create_clihost_memctrl:
	device_remove_file(dev, &dev_attr_clihost_priblk);
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
	device_remove_file(dev, &dev_attr_clihost_memctrl);
}
