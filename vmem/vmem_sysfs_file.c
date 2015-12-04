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

void IP_convert(struct in_addr *ip, unsigned char *str, unsigned int buflen) {
	snprintf(str, buflen, "%d.%d.%d.%d", ((unsigned char *)&(ip->s_addr))[0], ((unsigned char *)&(ip->s_addr))[1], ((unsigned char *)&(ip->s_addr))[2], ((unsigned char *)&(ip->s_addr))[3]);
}

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
			out += sprintf(out, "%lx\t",
						(unsigned long)Devices->addr_entry[nIndex].entry.vmem.blk_remote_addr);
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

	if(count != sizeof(struct MsgCliOp)) {
		printk(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	cliop = (struct MsgCliOp *)kmalloc(sizeof(struct MsgCliOp), GFP_KERNEL);
	memcpy(cliop, buf, count);
	switch(cliop->op) {
		//add server
		case CLIHOST_OP_ADD_SERHOST: {
			IP_convert(&cliop->info.addser.host_addr, IPaddr, IP_ADDR_LEN);
			printk(KERN_INFO"vmem:server add\n");
			printk(KERN_INFO"name:%s,addr:%s", cliop->info.addser.host_name, IPaddr);
			//allocate memory and copy to memory
			serhostnew = (struct server_host *)kmem_cache_alloc(Devices->slab_server_host, GFP_KERNEL);
			memset(serhostnew, 0, sizeof(struct server_host));
			memcpy(serhostnew->host_name, cliop->info.addser.host_name, HOST_NAME_LEN);
			memcpy(&serhostnew->host_addr.sin_addr, &cliop->info.addser.host_addr, sizeof(struct in_addr));
			memcpy(&serhostnew->block_available, &cliop->info.addser.block_num, sizeof(unsigned int));
			//search for existing
			mutex_lock(&Devices->lshd_inuse_mutex);
			list_for_each(p, &Devices->lshd_inuse) {
				serhost = list_entry(p, struct server_host, ls_inuse);
				if(!memcmp(&serhostnew->host_addr.sin_addr.s_addr,
								&serhost->host_addr.sin_addr.s_addr, sizeof(struct in_addr))) {
					printk(KERN_INFO"vmem:server add:same server\n");
					break;
				}
			}
			mutex_unlock(&Devices->lshd_inuse_mutex);
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each(p, &Devices->lshd_available) {
				serhost = list_entry(p, struct server_host, ls_available);
				if(!memcmp(&serhostnew->host_addr.sin_addr.s_addr,
								&serhost->host_addr.sin_addr.s_addr, sizeof(struct in_addr))) {
					printk(KERN_INFO"vmem:server add:same server\n");
					break;
				}
			}
			mutex_unlock(&Devices->lshd_avail_mutex);

			//add to list
			if(p == &Devices->lshd_available) {
				mutex_init(&serhostnew->ptr_mutex);
				mutex_init(&serhostnew->lshd_req_msg_mutex);
				mutex_init(&serhostnew->lshd_wrdata_mutex);
				INIT_LIST_HEAD(&serhostnew->lshd_req_msg);
				INIT_LIST_HEAD(&serhostnew->lshd_wrdata);
				serhostnew->slab_netmsg_req = Devices->slab_netmsg_req;
				serhostnew->slab_netmsg_data = Devices->slab_netmsg_data;
				mutex_lock(&Devices->lshd_avail_mutex);
				list_add_tail(&serhostnew->ls_available, &Devices->lshd_available);
				mutex_unlock(&Devices->lshd_avail_mutex);

			}
			else {
				kmem_cache_free(Devices->slab_server_host, serhostnew);
				goto err_ser_exist;
			}
			break;
		}
		//modify server
		case CLIHOST_OP_MOD_SERHOST: {
			IP_convert(&cliop->info.modser.host_addr, IPaddr, IP_ADDR_LEN);
			printk(KERN_INFO"vmem:server modify\n");
			printk(KERN_INFO"addr:%s", IPaddr);

			//search for existing
			mutex_lock(&Devices->lshd_inuse_mutex);
			list_for_each(p, &Devices->lshd_inuse) {
				serhost = list_entry(p, struct server_host, ls_inuse);
				if(!memcmp(&serhost->host_addr.sin_addr.s_addr,
								&cliop->info.modser.host_addr.s_addr, sizeof(struct in_addr))) {
					serhost->block_available = cliop->info.modser.block_num;
					break;
				}
			}
			mutex_unlock(&Devices->lshd_inuse_mutex);
			if(p != &Devices->lshd_inuse) {
				break;
			}
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each(p, &Devices->lshd_available) {
				serhost = list_entry(p, struct server_host, ls_available);
				if(!memcmp(&serhost->host_addr.sin_addr.s_addr,
								&cliop->info.modser.host_addr.s_addr, sizeof(struct in_addr))) {
					serhost->block_available = cliop->info.modser.block_num;
					break;
				}
			}
			mutex_unlock(&Devices->lshd_avail_mutex);
			break;
		}
		//map local memory
		case CLIHOST_OP_MAP_LOCAL:{
			int nCount = 0, nBlk = 0, nIndex = 0;
			printk(KERN_INFO"vmem:map local\n");
			nBlk = cliop->info.maplocal.block_num;
			printk(KERN_INFO"vmem:map local num:%d\n", nBlk);
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
		//delete server host available
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
		//delete server host inuse
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

//alloc page
static ssize_t clihost_alloc_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgMemAlloc memalloc;
	unsigned int nIndex = 0;
	unsigned int nCount = 0;
	unsigned int nPageIndex = 0;

	if(count != sizeof(struct MsgMemAlloc)) {
		printk(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	memcpy(&memalloc, buf, count);
	if(memalloc.vpagenum > VPAGE_PER_ALLOC) {
		printk(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
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
	return count;
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
		printk(KERN_INFO"page:%lx\n", memret.vpageaddr[nIndex]);
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
		printk(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	memcpy(&memfree, buf, count);
	if(memfree.vpagenum > VPAGE_PER_ALLOC) {
		printk(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}

	for(nIndex = 0; nIndex < memfree.vpagenum; nIndex++) {
		nBlkIndex = GET_BLK_INDEX(memfree.vpageaddr[nIndex]);
		nPageIndex = GET_VPAGE_INDEX(memfree.vpageaddr[nIndex]);
		if(nBlkIndex > BLK_NUM_MAX || nPageIndex > VPAGE_NUM_IN_BLK)
		  continue;

		printk(KERN_INFO"blk:%d,vpage:%d\n", nBlkIndex, nPageIndex);
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

//read page
static ssize_t clihost_read_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgMemRead memread;
	unsigned int nBlkIndex = 0;
	unsigned int nPageIndex = 0;

	if(count != sizeof(struct MsgMemRead)) {
		printk(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}

	memcpy(&memread, buf, sizeof(struct MsgMemRead));

	nBlkIndex = GET_BLK_INDEX(memread.vpageaddr);
	nPageIndex = GET_VPAGE_INDEX(memread.vpageaddr);

	printk(KERN_INFO"blk:%d,vpage:%d\n", nBlkIndex, nPageIndex);
	if(nBlkIndex > BLK_NUM_MAX || nPageIndex > VPAGE_NUM_IN_BLK) {
		printk(KERN_INFO"vmem:%s:illegal address\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}

	if(!Devices->addr_entry[nBlkIndex].inuse) {
		printk(KERN_INFO"vmem:%s:memory not mapped\n", __FUNCTION__);
		return ERR_VMEM_NOT_MAPPED;
	}
	if(!Devices->addr_entry[nBlkIndex].page_bitmap[nPageIndex]) {
		printk(KERN_INFO"vmem:%s:page not used\n", __FUNCTION__);
		return ERR_VMEM_PAGE_NOT_USED;
	}
	//vpage in native
	if(Devices->addr_entry[nBlkIndex].native) {
		mutex_lock(&Devices->addr_entry[nBlkIndex].handle_mutex);
		mutex_lock(&Devices->vpage_read->access_mutex);

		Devices->vpage_read->vpageaddr = memread.vpageaddr;
		memcpy(Devices->vpage_read->Data, 
					Devices->addr_entry[nBlkIndex].entry.native.addr + nPageIndex * VPAGE_SIZE,
					VPAGE_SIZE);

		mutex_unlock(&Devices->vpage_read->access_mutex);
		mutex_unlock(&Devices->addr_entry[nBlkIndex].handle_mutex);
	}
	//vpage in remote
	else if(Devices->addr_entry[nBlkIndex].remote){
		struct netmsg_req * msg_req = NULL;
		struct server_host *serhost = NULL;
		serhost = Devices->addr_entry[nBlkIndex].entry.vmem.serhost;
		if(!serhost) {
			goto err_null_ptr;
		}
		msg_req = (struct netmsg_req *)kmem_cache_alloc(serhost->slab_netmsg_req, GFP_USER);
		memset((void *)msg_req, 0, sizeof(struct netmsg_req));

		//post read msg to list
		msg_req->msgID = NETMSG_CLI_REQUEST_READ;
		msg_req->info.req_read.vpageaddr = memread.vpageaddr;
		msg_req->info.req_read.remoteIndex
			= Devices->addr_entry[nBlkIndex].entry.vmem.blk_remote_index;
		msg_req->info.req_read.pageIndex = nPageIndex;
		mutex_lock(&serhost->lshd_req_msg_mutex);
		list_add_tail(&msg_req->ls_reqmsg, &serhost->lshd_req_msg);
		mutex_unlock(&serhost->lshd_req_msg_mutex);
		printk(KERN_INFO"add read msg in inuse server\n");
	}

err_null_ptr:
	return count;
}
static ssize_t clihost_read_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char * out = buf;
	struct MsgMemReadRet *pmemreadret = NULL;

	pmemreadret = (struct MsgMemReadRet *)kmalloc(sizeof(struct MsgMemReadRet), GFP_USER);

	mutex_lock(&Devices->vpage_read->access_mutex);

	pmemreadret->vpageaddr = Devices->vpage_read->vpageaddr;
	printk(KERN_INFO"vpage addr:%lx\n", pmemreadret->vpageaddr);
	memcpy((void *)pmemreadret->Data, (void *)Devices->vpage_read->Data, VPAGE_SIZE);
	memcpy((void *)out, (void *)pmemreadret, sizeof(struct MsgMemRet));
	out += sizeof(struct MsgMemRet);

	mutex_unlock(&Devices->vpage_read->access_mutex);

	kfree(pmemreadret);

	return out - buf;
}
static DEVICE_ATTR(clihost_read, S_IWUSR|S_IRUSR, clihost_read_show, clihost_read_store);

//write page
static ssize_t clihost_write_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgMemWrite *pmemwrite = NULL;
	unsigned int nBlkIndex = 0;
	unsigned int nPageIndex = 0;

	printk(KERN_INFO"vmem:page write\n");
	if(count != sizeof(struct MsgMemWrite)) {
		printk(KERN_INFO"vmem:%s:illegal input\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	pmemwrite = (struct MsgMemWrite *)kmalloc(sizeof(struct MsgMemWrite), GFP_USER);
	memcpy(pmemwrite, buf, sizeof(struct MsgMemWrite));

	nBlkIndex = GET_BLK_INDEX(pmemwrite->vpageaddr);
	nPageIndex = GET_VPAGE_INDEX(pmemwrite->vpageaddr);
	
	if(nBlkIndex > BLK_NUM_MAX || nPageIndex > VPAGE_NUM_IN_BLK) {
		printk(KERN_INFO"vmem:%s:illegal address\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	if(!Devices->addr_entry[nBlkIndex].inuse) {
		printk(KERN_INFO"vmem:%s:memory not mapped\n", __FUNCTION__);
		return ERR_VMEM_NOT_MAPPED;
	}
	if(!Devices->addr_entry[nBlkIndex].page_bitmap[nPageIndex]) {
		printk(KERN_INFO"vmem:%s:page not used\n", __FUNCTION__);
		return ERR_VMEM_PAGE_NOT_USED;
	}
	printk(KERN_INFO"vmem:%s:page write:%s\n", __FUNCTION__, pmemwrite->Data);
	//vpage in native
	if(Devices->addr_entry[nBlkIndex].native) {
		mutex_lock(&Devices->addr_entry[nBlkIndex].handle_mutex);
		memcpy(Devices->addr_entry[nBlkIndex].entry.native.addr + nPageIndex * VPAGE_SIZE,
					pmemwrite->Data, VPAGE_SIZE);
		mutex_unlock(&Devices->addr_entry[nBlkIndex].handle_mutex);
	}
	//vpage in remote
	else if(Devices->addr_entry[nBlkIndex].remote){
		struct netmsg_req * msg_req = NULL;
		struct netmsg_data * msg_wrdata = NULL;
		struct server_host *serhost = NULL;
		serhost = Devices->addr_entry[nBlkIndex].entry.vmem.serhost;
		if(!serhost) {
			goto err_null_ptr;
		}
		msg_req = (struct netmsg_req *)kmem_cache_alloc(serhost->slab_netmsg_req, GFP_USER);
		msg_wrdata = (struct netmsg_data *)kmem_cache_alloc(serhost->slab_netmsg_data, GFP_USER);
		memset((void *)msg_req, 0, sizeof(struct netmsg_req));
		memset((void *)msg_wrdata, 0, sizeof(struct netmsg_data));

		//post write msg to list
		msg_req->msgID = NETMSG_CLI_REQUEST_WRITE;
		msg_req->info.req_write.vpageaddr = pmemwrite->vpageaddr;
		msg_req->info.req_write.remoteIndex
			= Devices->addr_entry[nBlkIndex].entry.vmem.blk_remote_index;
		msg_req->info.req_write.pageIndex = nPageIndex;
		mutex_lock(&serhost->lshd_req_msg_mutex);
		list_add_tail(&msg_req->ls_reqmsg, &serhost->lshd_req_msg);
		mutex_unlock(&serhost->lshd_req_msg_mutex);
		printk(KERN_INFO"add write msg in inuse server\n");

		//post data to list
		memcpy(msg_wrdata->data, pmemwrite->Data, VPAGE_SIZE);
		mutex_lock(&serhost->lshd_wrdata_mutex);
		list_add_tail(&msg_wrdata->ls_req, &serhost->lshd_wrdata);
		mutex_unlock(&serhost->lshd_wrdata_mutex);
		printk(KERN_INFO"add write data in inuse server\n");

	}

err_null_ptr:
	kfree(pmemwrite);
	return count;
}
static DEVICE_ATTR(clihost_write, S_IWUSR, NULL, clihost_write_store);

int create_sysfs_file(struct device *dev) {
	int ret = KERERR_SUCCESS;
	
	if(!dev) {
		ret = KERERR_NULL_PTR;
		goto err_null_ptr;
	}
	ret = device_create_file(dev, &dev_attr_clihost_priser);
	if (ret) {
		printk(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_priser;
	}

	ret = device_create_file(dev, &dev_attr_clihost_op);
	if (ret) {
		printk(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_op;
	}

	ret = device_create_file(dev, &dev_attr_clihost_priblk);
	if (ret) {
		printk(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_priblk;
	}

	ret = device_create_file(dev, &dev_attr_clihost_alloc);
	if (ret) {
		printk(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_alloc;
	}

	ret = device_create_file(dev, &dev_attr_clihost_free);
	if (ret) {
		printk(KERN_INFO"vmem:create sysfs file error: %d", ret);
		ret = KERERR_CREATE_FILE;
		goto err_sys_create_clihost_free;
	}

//	ret = device_create_file(dev, &dev_attr_clihost_read);
//	if (ret) {
//		printk(KERN_INFO"vmem:create sysfs file error: %d", ret);
//		ret = KERERR_CREATE_FILE;
//		goto err_sys_create_clihost_read;
//	}
//
//	ret = device_create_file(dev, &dev_attr_clihost_write);
//	if (ret) {
//		printk(KERN_INFO"vmem:create sysfs file error: %d", ret);
//		ret = KERERR_CREATE_FILE;
//		goto err_sys_create_clihost_write;
//	}

	return ret;
//err_sys_create_clihost_write:
//	device_remove_file(dev, &dev_attr_clihost_read);
//err_sys_create_clihost_read:
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
//	device_remove_file(dev, &dev_attr_clihost_read);
//	device_remove_file(dev, &dev_attr_clihost_write);
}
