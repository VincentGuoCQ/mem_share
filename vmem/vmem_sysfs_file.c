#include "../include.h"
#include "../common.h"
#include "../kererr.h"
#include "vmem_common.h"
#include "userspace/errors.h"
#include "userspace/msgfmt.h"
#include "../net_msg.h"

extern struct vmem_dev *Devices;

char * blk_state_str[] = {
	"null",
	"native",
	"remote",
	NULL,
};
unsigned int state_to_str(struct cli_blk * blk) {
	if(!blk->inuse)
	  return 0;
	if(blk->remote)
	  return 2;
	if(blk->native)
	  return 1;
	return 0;
}

int vmem_serhost_init(struct server_host *serhost);

void IP_convert(struct in_addr *ip, unsigned char *str, unsigned int buflen) {
	snprintf(str, buflen, "%d.%d.%d.%d", ((unsigned char *)&(ip->s_addr))[0], ((unsigned char *)&(ip->s_addr))[1], ((unsigned char *)&(ip->s_addr))[2], ((unsigned char *)&(ip->s_addr))[3]);
}

int bind_to_device(struct socket *sock, char *ifname);
int connect_to_addr(struct socket *sock, struct server_host *serhost, unsigned short port);

//print server
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

	mutex_lock(&Devices->lshd_serhost_mutex);
	list_for_each(p, &Devices->lshd_serhost) {
		ps = list_entry(p, struct server_host, ls_serhost);
		IP_convert(&ps->host_addr.sin_addr, IPaddr, IP_ADDR_LEN);
		out += sprintf(out, "%s\t\t%s\t\t%d\t\tconnected\n",
					ps->host_name, IPaddr, ps->block_available);
	}
	mutex_unlock(&Devices->lshd_serhost_mutex);
	return out - buf;
}
static DEVICE_ATTR_RO(clihost_priser);

//print block
static ssize_t clihost_priblk_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char *out = buf;
	int nIndex = 0;

	if(!Devices) {
		return 0;
	}
	
	out += sprintf(out, "Block Index\tState\tAddress\tinuse page\n");
	out += sprintf(out, "----------------------------------\n");
	for(nIndex = 0; nIndex < BLK_NUM_MAX; nIndex++) {
		mutex_lock(&Devices->addr_entry[nIndex].handle_mutex);
		out += sprintf(out, "%d\t\t%s\t", nIndex, blk_state_str[state_to_str(&Devices->addr_entry[nIndex])]);
		if(Devices->addr_entry[nIndex].native) {
			out += sprintf(out, "%lx\t", (unsigned long)Devices->addr_entry[nIndex].entry.native.addr);
		}
		else {
			out += sprintf(out, "NULL\t");
		}
		out += sprintf(out, "%d\n", Devices->addr_entry[nIndex].inuse_page);
		mutex_unlock(&Devices->addr_entry[nIndex].handle_mutex);
	}
	return out - buf;
}
	
static DEVICE_ATTR_RO(clihost_priblk);

//operation
static ssize_t clihost_op_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgCliOp * cliop = NULL;
	struct server_host *serhost = NULL;
	struct server_host *serhostnew = NULL;
	struct list_head *p = NULL, *next = NULL;
	char IPaddr[IP_ADDR_LEN];
	int ret = count;

	if(count != sizeof(struct MsgCliOp)) {
		KER_DEBUG(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	cliop = (struct MsgCliOp *)kmalloc(sizeof(struct MsgCliOp), GFP_KERNEL);
	memcpy(cliop, buf, count);
	switch(cliop->op) {
		//add server
		case CLIHOST_OP_ADD_SERHOST: {
			IP_convert(&cliop->info.addser.host_addr, IPaddr, IP_ADDR_LEN);
			KER_DEBUG(KERN_INFO"vmem:server add\n");
			KER_DEBUG(KERN_INFO"name:%s,addr:%s", cliop->info.addser.host_name, IPaddr);
			//allocate memory and copy to memory
			serhostnew = (struct server_host *)kmem_cache_alloc(Devices->slab_server_host, GFP_KERNEL);
			memset(serhostnew, 0, sizeof(struct server_host));
			memcpy(serhostnew->host_name, cliop->info.addser.host_name, HOST_NAME_LEN);
			memcpy(&serhostnew->host_addr.sin_addr, &cliop->info.addser.host_addr, sizeof(struct in_addr));
			memcpy(&serhostnew->block_available, &cliop->info.addser.block_num, sizeof(unsigned int));
			//search for existing
			mutex_lock(&Devices->lshd_serhost_mutex);
			list_for_each(p, &Devices->lshd_serhost) {
				serhost = list_entry(p, struct server_host, ls_serhost);
				if(!memcmp(&serhostnew->host_addr.sin_addr.s_addr,
								&serhost->host_addr.sin_addr.s_addr, sizeof(struct in_addr))) {
					KER_DEBUG(KERN_INFO"vmem:server add:same server\n");
					break;
				}
			}
			mutex_unlock(&Devices->lshd_serhost_mutex);

			//add to list
			if(p == &Devices->lshd_serhost) {
				//if tcp to server established, add server to list
				if(vmem_serhost_init(serhostnew) == KERERR_SUCCESS) {
					KER_DEBUG(KERN_INFO"add server to list\n");
					mutex_lock(&Devices->lshd_serhost_mutex);
					list_add_tail(&serhostnew->ls_serhost, &Devices->lshd_serhost);
					mutex_unlock(&Devices->lshd_serhost_mutex);
				}
				//if tcp to server not established, delete server
				else {
					KER_DEBUG(KERN_INFO"tcp connection not establist\n");
					kmem_cache_free(Devices->slab_server_host, serhostnew);
					ret = ERR_CLI_CONN_REFUSED;
					goto err_conn_refused; 
				}

			}
			else {
				kmem_cache_free(Devices->slab_server_host, serhostnew);
				ret = ERR_CLI_SER_EXIST;
				goto err_ser_exist;
			}
			break;
		}
		//modify server
		case CLIHOST_OP_MOD_SERHOST: {
			IP_convert(&cliop->info.modser.host_addr, IPaddr, IP_ADDR_LEN);
			KER_DEBUG(KERN_INFO"vmem:server modify\n");
			KER_DEBUG(KERN_INFO"addr:%s", IPaddr);

			//search for existing
			mutex_lock(&Devices->lshd_serhost_mutex);
			list_for_each(p, &Devices->lshd_serhost) {
				serhost = list_entry(p, struct server_host, ls_serhost);
				if(!memcmp(&serhost->host_addr.sin_addr.s_addr,
								&cliop->info.modser.host_addr.s_addr, sizeof(struct in_addr))) {
					serhost->block_available = cliop->info.modser.block_num;
					break;
				}
			}
			mutex_unlock(&Devices->lshd_serhost_mutex);
			break;
		}
		//map local memory
		case CLIHOST_OP_MAP_LOCAL:{
			int nCount = 0, nBlk = 0, nIndex = 0;
			KER_DEBUG(KERN_INFO"vmem:map local\n");
			nBlk = cliop->info.maplocal.block_num;
			KER_DEBUG(KERN_INFO"vmem:map local num:%d\n", nBlk);
			if(!Devices->addr_entry) {
				goto err_null_ptr;
			}
			for(nIndex = 0; nIndex < BLK_NUM_MAX && 
						nCount < cliop->info.maplocal.block_num; nIndex++) {
				if(FALSE == (Devices->addr_entry[nIndex].inuse)) {
					mutex_lock(&Devices->addr_entry[nIndex].handle_mutex);
					Devices->addr_entry[nIndex].entry.native.pages =
						alloc_pages(GFP_USER, BLK_SIZE_SHIFT-PAGE_SHIFT);
					Devices->addr_entry[nIndex].entry.native.addr 
						= kmap(Devices->addr_entry[nIndex].entry.native.pages);
					Devices->addr_entry[nIndex].native = TRUE;
					Devices->addr_entry[nIndex].inuse = TRUE;
					mutex_unlock(&Devices->addr_entry[nIndex].handle_mutex);
					nCount++;
				} 
			}
			break;
		}
		//delete server host inuse
		case CLIHOST_OP_DEL_SERHOST_INUSE: {
			mutex_lock(&Devices->lshd_serhost_mutex);
			list_for_each_safe(p, next, &Devices->lshd_serhost) {
				struct list_head *sp = NULL, *snext = NULL;
				struct netmsg_req *netmsg_req = NULL;
				serhost = list_entry(p, struct server_host, ls_serhost);
				mutex_lock(&serhost->lshd_req_msg_mutex);
				list_for_each_safe(sp, snext, &serhost->lshd_req_msg) {
					netmsg_req = list_entry(sp, struct netmsg_req, ls_reqmsg);
					list_del(&netmsg_req->ls_reqmsg);
					kmem_cache_free(serhost->slab_netmsg_req, netmsg_req);
				}
				mutex_unlock(&serhost->lshd_req_msg_mutex);
				KER_DEBUG(KERN_INFO"vmem:delete serverhost netmsg req\n");

				mutex_lock(&serhost->ptr_mutex);
				if(serhost->sock) {
					sock_release(serhost->sock);
					serhost->sock = NULL;
				}
				mutex_unlock(&serhost->ptr_mutex);
				KER_DEBUG(KERN_INFO"vmem:delete serverhost sock\n");
				if(serhost->SerSendThread) {
					kthread_stop(serhost->SerSendThread);
					serhost->SerSendThread = NULL;
				}
				KER_DEBUG(KERN_INFO"vmem:delete serverhost send thread\n");

				list_del(&serhost->ls_serhost);
				kmem_cache_free(Devices->slab_server_host, serhost);
			}
			mutex_unlock(&Devices->lshd_serhost_mutex);
			KER_DEBUG(KERN_INFO"vmem:delete serverhost list\n");
			break;
		}
	}

	kfree(cliop);
	return count;
err_conn_refused:
err_ser_exist:
	kfree(cliop);
	return ERR_VMEM_HOST_EXIST;
err_null_ptr:
	kfree(cliop);
	return ERR_VMEM_NULL_PTR;
}
static DEVICE_ATTR_WO(clihost_op);

//alloc page
static ssize_t clihost_alloc_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgMemAlloc memalloc;
	unsigned int nIndex = 0;
	unsigned int nCount = 0;
	unsigned int nPageIndex = 0;
    int ret = count;

	if(count != sizeof(struct MsgMemAlloc)) {
		KER_DEBUG(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	memcpy(&memalloc, buf, count);
	if(memalloc.vpagenum > VPAGE_PER_ALLOC) {
		KER_DEBUG(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	mutex_lock(&Devices->vpage_alloc->access_mutex);

	for(nIndex = 0; nIndex < BLK_NUM_MAX
			&& nCount < memalloc.vpagenum; nIndex++) {
		mutex_lock(&Devices->addr_entry[nIndex].handle_mutex);
		if(Devices->addr_entry[nIndex].inuse
				&& Devices->addr_entry[nIndex].inuse_page < VPAGE_NUM_IN_BLK) {
			for(nPageIndex = 0; nPageIndex < VPAGE_NUM_IN_BLK
						&& nCount < memalloc.vpagenum; nPageIndex++) {
				if(FALSE == Devices->addr_entry[nIndex].page_bitmap[nPageIndex]) {
					Devices->vpage_alloc->vpageaddr[nCount] =
						(nIndex << BLK_SIZE_SHIFT |
						 nPageIndex << VPAGE_SIZE_SHIFT);
					Devices->addr_entry[nIndex].page_bitmap[nPageIndex] = TRUE;
					Devices->addr_entry[nIndex].inuse_page++;
					nCount++;
				}
			}
		}
		mutex_unlock(&Devices->addr_entry[nIndex].handle_mutex);
	}
	Devices->vpage_alloc->vpagenum = nCount;
	mutex_unlock(&Devices->vpage_alloc->access_mutex);
	return ret;
}
static ssize_t clihost_alloc_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char *out = buf;
	struct MsgMemRet memret;
	unsigned int nIndex = 0;
	memset(&memret, 0, sizeof(struct MsgMemRet));
	memret.vpagenum = Devices->vpage_alloc->vpagenum;
	mutex_lock(&Devices->vpage_alloc->access_mutex);
	for(nIndex = 0; nIndex < Devices->vpage_alloc->vpagenum; nIndex++) {
		memret.vpageaddr[nIndex] = Devices->vpage_alloc->vpageaddr[nIndex];
		KER_DEBUG(KERN_INFO"page:%lx\n", memret.vpageaddr[nIndex]);
	}
	mutex_unlock(&Devices->vpage_alloc->access_mutex);

	memcpy((void *)out, (void *)&memret, sizeof(struct MsgMemRet));
	out += sizeof(struct MsgMemRet);
	return out-buf;
}
static DEVICE_ATTR(clihost_alloc, S_IWUSR|S_IRUSR, clihost_alloc_show, clihost_alloc_store);

//free page
static ssize_t clihost_free_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgMemFree memfree;
	unsigned int nIndex = 0;
	unsigned int nBlkIndex = 0;
	unsigned int nPageIndex = 0;

	if(count != sizeof(struct MsgMemFree)) {
		KER_DEBUG(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	memcpy(&memfree, buf, count);
	if(memfree.vpagenum > VPAGE_PER_ALLOC) {
		KER_DEBUG(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}

	for(nIndex = 0; nIndex < memfree.vpagenum; nIndex++) {
		nBlkIndex = GET_BLK_INDEX(memfree.vpageaddr[nIndex]);
		nPageIndex = GET_VPAGE_INDEX(memfree.vpageaddr[nIndex]);
		if(nBlkIndex > BLK_NUM_MAX || nPageIndex > VPAGE_NUM_IN_BLK)
		  continue;

		KER_DEBUG(KERN_INFO"blk:%d,vpage:%d\n", nBlkIndex, nPageIndex);
		mutex_lock(&Devices->addr_entry[nBlkIndex].handle_mutex);
		if(Devices->addr_entry[nBlkIndex].page_bitmap[nPageIndex]) {
			Devices->addr_entry[nBlkIndex].page_bitmap[nPageIndex] = FALSE;
			Devices->addr_entry[nBlkIndex].inuse_page--;
		}
		mutex_unlock(&Devices->addr_entry[nBlkIndex].handle_mutex);
	}

	return count;
}
static DEVICE_ATTR_WO(clihost_free);

int create_sysfs_file(struct device *dev) {
	int ret = KERERR_SUCCESS;
	
	if(!dev) {
		ret = KERERR_NULL_PTR;
		goto err_null_ptr;
	}
	ret = device_create_file(dev, &dev_attr_clihost_priser);
	if (ret) {
		KER_DEBUG(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_priser;
	}

	ret = device_create_file(dev, &dev_attr_clihost_op);
	if (ret) {
		KER_DEBUG(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_op;
	}

	ret = device_create_file(dev, &dev_attr_clihost_priblk);
	if (ret) {
		KER_DEBUG(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_priblk;
	}

	ret = device_create_file(dev, &dev_attr_clihost_alloc);
	if (ret) {
		KER_DEBUG(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_alloc;
	}

	ret = device_create_file(dev, &dev_attr_clihost_free);
	if (ret) {
		KER_DEBUG(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_free;
	}

	return ret;
	device_remove_file(dev, &dev_attr_clihost_free);
err_sys_create_clihost_free:
	device_remove_file(dev, &dev_attr_clihost_alloc);
err_sys_create_clihost_alloc:
	device_remove_file(dev, &dev_attr_clihost_priblk);
err_sys_create_clihost_priblk:
	device_remove_file(dev, &dev_attr_clihost_op);
err_sys_create_clihost_op:
	device_remove_file(dev, &dev_attr_clihost_priser);
err_sys_create_clihost_priser:
err_null_ptr:
	return ret;
}
void delete_sysfs_file(struct device *dev) {
	device_remove_file(dev, &dev_attr_clihost_priser);
	device_remove_file(dev, &dev_attr_clihost_op);
	device_remove_file(dev, &dev_attr_clihost_priblk);
	device_remove_file(dev, &dev_attr_clihost_alloc);
	device_remove_file(dev, &dev_attr_clihost_free);
}
