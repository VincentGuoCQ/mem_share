#include "../include.h"
#include "../kererr.h"
#include "../common.h"
#include "vmem_common.h"
#include "userspace/errors.h"
#include "../net_msg.h"

struct vmem_dev *Devices = NULL;
struct cli_blk blktable[BLK_NUM_MAX];
struct vpage_alloc vpage_alloc;

int vmem_open(struct inode *inode, struct file *filp) {
	filp->private_data = Devices;
	return ERR_SUCCESS;
}

int vmem_release(struct inode *inode, struct file *filp) {
	return 0;
}

static ssize_t vmem_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos) {
	struct vmem_dev *dev =filp->private_data;
	unsigned int nBlkIndex = 0;
	unsigned int nPageIndex = 0;

	KER_PRT(KERN_INFO"begin to read:%ld\n", jiffies);

	nBlkIndex = GET_BLK_INDEX(*ppos);
	nPageIndex = GET_VPAGE_INDEX(*ppos);

	KER_DEBUG(KERN_INFO"blk:%d,vpage:%d\n", nBlkIndex, nPageIndex);
	if(nBlkIndex > BLK_NUM_MAX || nPageIndex > VPAGE_NUM_IN_BLK) {
		KER_DEBUG(KERN_INFO"vmem:%s:illegal address\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	if(count > VPAGE_SIZE) {
		KER_DEBUG(KERN_INFO"vmem:%s:page size too large\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	if(!dev->addr_entry[nBlkIndex].inuse) {
		KER_DEBUG(KERN_INFO"vmem:%s:memory not mapped\n", __FUNCTION__);
		return ERR_VMEM_NOT_MAPPED;
	}
	if(!dev->addr_entry[nBlkIndex].page_bitmap[nPageIndex]) {
		KER_DEBUG(KERN_INFO"vmem:%s:page not used\n", __FUNCTION__);
		return ERR_VMEM_PAGE_NOT_USED;
	}
	//vpage in native
	if(dev->addr_entry[nBlkIndex].native) {
		mutex_lock(&dev->addr_entry[nBlkIndex].handle_mutex);

		copy_to_user(buf, 
					dev->addr_entry[nBlkIndex].entry.native.addr + nPageIndex * VPAGE_SIZE,
					count);

		mutex_unlock(&dev->addr_entry[nBlkIndex].handle_mutex);
		KER_PRT(KERN_INFO"end to read:%ld\n", jiffies);
		return count;
	}
	//vpage in remote
	else if(dev->addr_entry[nBlkIndex].remote){
		struct netmsg_req * msg_req = NULL;
		struct server_host *serhost = NULL;
		struct list_head *p = NULL, *next = NULL;
		struct netmsg_data *msg_rddata = NULL;
		serhost = dev->addr_entry[nBlkIndex].entry.vmem.serhost;
		if(!serhost) {
			goto err_null_ptr;
		}
		msg_req = (struct netmsg_req *)kmem_cache_alloc(serhost->slab_netmsg_req, GFP_USER);
		memset((void *)msg_req, 0, sizeof(struct netmsg_req));

		//post read msg to list
		msg_req->msgID = NETMSG_CLI_REQUEST_READ;
		msg_req->info.req_write.vpageaddr = (unsigned long)*ppos;
		msg_req->info.req_read.remoteIndex
			= dev->addr_entry[nBlkIndex].entry.vmem.blk_remote_index;
		msg_req->info.req_read.pageIndex = nPageIndex;
		mutex_lock(&serhost->lshd_req_msg_mutex);
		list_add_tail(&msg_req->ls_reqmsg, &serhost->lshd_req_msg);
		mutex_unlock(&serhost->lshd_req_msg_mutex);
		KER_DEBUG(KERN_INFO"add read msg in server\n");
		while(1) {
			schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
			mutex_lock(&Devices->lshd_read_mutex);
			list_for_each_safe(p, next, &Devices->lshd_read) {
				msg_rddata = list_entry(p, struct netmsg_data, ls_req); 
				if(msg_rddata->vpageaddr == *ppos) {
					copy_to_user(buf, msg_rddata->data, count);
					list_del(p);
					kmem_cache_free(Devices->slab_netmsg_data, msg_rddata);
					mutex_unlock(&Devices->lshd_read_mutex);
					KER_PRT(KERN_INFO"end to read:%ld\n", jiffies);
					return count;
				}
			}
			mutex_unlock(&Devices->lshd_read_mutex);
		}

	}

err_null_ptr:
	return count;
}

static ssize_t vmem_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos) {
	struct vmem_dev *dev =filp->private_data;
	unsigned int nBlkIndex = 0;
	unsigned int nPageIndex = 0;

	KER_PRT(KERN_INFO"begin to write:%ld\n", jiffies);

	nBlkIndex = GET_BLK_INDEX(*ppos);
	nPageIndex = GET_VPAGE_INDEX(*ppos);

	KER_DEBUG(KERN_INFO"blk:%d,vpage:%d\n", nBlkIndex, nPageIndex);
	if(nBlkIndex > BLK_NUM_MAX || nPageIndex > VPAGE_NUM_IN_BLK) {
		KER_DEBUG(KERN_INFO"vmem:%s:illegal address\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}
	if(count > VPAGE_SIZE) {
		KER_DEBUG(KERN_INFO"vmem:%s:page size too large\n", __FUNCTION__);
		return ERR_VMEM_ARG_ILLEGAL;
	}

	if(!dev->addr_entry[nBlkIndex].inuse) {
		KER_DEBUG(KERN_INFO"vmem:%s:memory not mapped\n", __FUNCTION__);
		return ERR_VMEM_NOT_MAPPED;
	}
	if(!dev->addr_entry[nBlkIndex].page_bitmap[nPageIndex]) {
		KER_DEBUG(KERN_INFO"vmem:%s:page not used\n", __FUNCTION__);
		return ERR_VMEM_PAGE_NOT_USED;
	}
	//vpage in native
	if(dev->addr_entry[nBlkIndex].native) {
		mutex_lock(&dev->addr_entry[nBlkIndex].handle_mutex);

		copy_from_user(dev->addr_entry[nBlkIndex].entry.native.addr + nPageIndex * VPAGE_SIZE,
					buf, count);

		mutex_unlock(&dev->addr_entry[nBlkIndex].handle_mutex);
	}
	//vpage in remote
	else if(dev->addr_entry[nBlkIndex].remote){
		struct netmsg_req * msg_req = NULL;
		struct netmsg_data * msg_wrdata = NULL;
		struct server_host *serhost = NULL;
		serhost = dev->addr_entry[nBlkIndex].entry.vmem.serhost;
		if(!serhost) {
			goto err_null_ptr;
		}
		msg_req = (struct netmsg_req *)kmem_cache_alloc(serhost->slab_netmsg_req, GFP_USER);
		msg_wrdata = (struct netmsg_data *)kmem_cache_alloc(serhost->slab_netmsg_data, GFP_USER);
		memset((void *)msg_req, 0, sizeof(struct netmsg_req));
		memset((void *)msg_wrdata, 0, sizeof(struct netmsg_data));

		//post write msg to list
		msg_req->msgID = NETMSG_CLI_REQUEST_WRITE;
		//msg_req->info.req_write.vpageaddr = pmemwrite->vpageaddr;
		msg_req->info.req_write.remoteIndex
			= dev->addr_entry[nBlkIndex].entry.vmem.blk_remote_index;
		msg_req->info.req_write.pageIndex = nPageIndex;
		mutex_lock(&serhost->lshd_req_msg_mutex);
		list_add_tail(&msg_req->ls_reqmsg, &serhost->lshd_req_msg);
		mutex_unlock(&serhost->lshd_req_msg_mutex);
		KER_DEBUG(KERN_INFO"add write msg in server\n");

		//post data to list
		copy_from_user(msg_wrdata->data, buf, count);
		mutex_lock(&serhost->lshd_wrdata_mutex);
		list_add_tail(&msg_wrdata->ls_req, &serhost->lshd_wrdata);
		mutex_unlock(&serhost->lshd_wrdata_mutex);
		KER_DEBUG(KERN_INFO"add write data in server\n");
	}

	KER_PRT(KERN_INFO"end to write:%ld\n", jiffies);

err_null_ptr:
	return count;
}

static loff_t vmem_llseek(struct file *filp, loff_t offset, int orig) {
	loff_t ret = ERR_SUCCESS;
	return ret;
}

static const struct file_operations vmem_fops = {
	.owner = THIS_MODULE,
	.llseek = vmem_llseek,
	.read = vmem_read,
	.write = vmem_write,
	.open = vmem_open,
	.release = vmem_release,
};

static void destory_device(struct vmem_dev *dev, int which) {
	int nIndex = 0;
	struct list_head *p = NULL, *next = NULL;
	struct server_host *pserhost = NULL;
	struct netmsg_data *preaddata = NULL;

	if(!dev) {
		return;
	}
	//kill daemon thread
	if(dev->DaemonThread) {
		kthread_stop(dev->DaemonThread);
	}
	KER_DEBUG(KERN_INFO"vmem:destory daemon thread\n");
	//destroy native block
	for(nIndex = 0; nIndex < BLK_NUM_MAX; nIndex++) {
		if(dev->addr_entry[nIndex].inuse && dev->addr_entry[nIndex].native) {
			kunmap(dev->addr_entry[nIndex].entry.native.pages);
			__free_pages(dev->addr_entry[nIndex].entry.native.pages, BLK_SIZE_SHIFT-PAGE_SHIFT);
			dev->addr_entry[nIndex].inuse = FALSE;
			dev->addr_entry[nIndex].native = FALSE;
		}
	}
	KER_DEBUG(KERN_INFO"vmem:destory native block\n");
	//destory read block list
	mutex_lock(&dev->lshd_read_mutex);
	list_for_each_safe(p, next, &dev->lshd_read) {
		preaddata = list_entry(p, struct netmsg_data, ls_req);
		list_del(&preaddata->ls_req);
		kmem_cache_free(dev->slab_netmsg_data, preaddata);
	}
	mutex_unlock(&dev->lshd_read_mutex);
	KER_DEBUG(KERN_INFO"vmem:destory serverhost read block list\n");

	//destory server host list 
	mutex_lock(&dev->lshd_serhost_mutex);
	list_for_each_safe(p, next, &dev->lshd_serhost) {
		struct list_head *sp = NULL, *snext = NULL;
		struct netmsg_req *netmsg_req = NULL;
		pserhost = list_entry(p, struct server_host, ls_serhost);

		mutex_lock(&pserhost->ptr_mutex);
		if(pserhost->sock) {
			sock_release(pserhost->sock);
			pserhost->sock = NULL;
		}
		if(pserhost->datasock) {
			sock_release(pserhost->datasock);
			pserhost->datasock = NULL;
		}
		mutex_unlock(&pserhost->ptr_mutex);
		KER_DEBUG(KERN_INFO"vmem:destory serverhost sock\n");

		if(pserhost->SerSendThread) {
			kthread_stop(pserhost->SerSendThread);
			pserhost->SerSendThread = NULL;
		}
		KER_DEBUG(KERN_INFO"vmem:destory serverhost send thread\n");

		if(pserhost->SerRecvThread) {
			kthread_stop(pserhost->SerRecvThread);
			pserhost->SerRecvThread = NULL;
		}
		KER_DEBUG(KERN_INFO"vmem:destory serverhost recv thread\n");

		mutex_lock(&pserhost->lshd_req_msg_mutex);
		list_for_each_safe(sp, snext, &pserhost->lshd_req_msg) {
			netmsg_req = list_entry(sp, struct netmsg_req, ls_reqmsg);
			list_del(&netmsg_req->ls_reqmsg);
			kmem_cache_free(pserhost->slab_netmsg_req, netmsg_req);
		}
		mutex_unlock(&pserhost->lshd_req_msg_mutex);

		list_del(&pserhost->ls_serhost);
		kmem_cache_free(dev->slab_server_host, pserhost);
	}
	mutex_unlock(&dev->lshd_serhost_mutex);
	KER_DEBUG(KERN_INFO"vmem:destory serverhost list\n");
	//delete slab
	if(dev->slab_server_host) {
		kmem_cache_destroy(dev->slab_server_host);
	}
	if(dev->slab_netmsg_req) {
		kmem_cache_destroy(dev->slab_netmsg_req);
	}
	if(dev->slab_netmsg_data) {
		kmem_cache_destroy(dev->slab_netmsg_data);
	}
	//delete sysfs file
	delete_sysfs_file(dev->dev);
	//delete dev
	cdev_del(&dev->gd);
	//delete sysfs dir
	device_destroy(dev->vmem_class, dev->devno);
	class_destroy(dev->vmem_class);
	//free data memory space
}

static int setup_device(struct vmem_dev *dev, dev_t devno) {
	int ret = KERERR_SUCCESS, nIndex = 0;
	memset(dev, 0, sizeof(struct vmem_dev));
	//init list head
	INIT_LIST_HEAD(&dev->lshd_serhost);
	INIT_LIST_HEAD(&dev->lshd_read);

	dev->devno = devno;
	//init dev	
	cdev_init(&dev->gd, &vmem_fops);
	dev->gd.owner = THIS_MODULE;
	ret = cdev_add(&dev->gd, dev->devno, 1);
	if(ret) {
		KER_DEBUG(KERN_NOTICE"Error %d adding vmem\n", ret);
		ret = KERERR_CREATE_DEVICE;
		goto err_create_device;
	}
	//create sysfs dir
	dev->vmem_class = class_create(THIS_MODULE, VMEM_NAME);
	dev->dev = device_create(dev->vmem_class, NULL, dev->devno, NULL, VMEM_NAME);
	//create sysfs file
	ret = create_sysfs_file(dev->dev);
	if(ret == KERERR_CREATE_FILE) {
		KER_DEBUG(KERN_NOTICE"vmem:create sysfs file fail\n");
		goto err_sysfs_create;
	}

	//create slab for server host
	dev->slab_server_host = kmem_cache_create("vmem_serhost",
				sizeof(struct server_host), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_server_host) {
		KER_DEBUG(KERN_NOTICE"vmem:create vmem_serhost slab fail\n");
		goto err_serhost_slab;
	}
	dev->slab_netmsg_req = kmem_cache_create("vmem_netmsg_req",
				sizeof(struct netmsg_req), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_netmsg_req) {
		KER_DEBUG(KERN_NOTICE"vmem:create vmem_serhost slab fail\n");
		goto err_netmsg_req_slab;
	}
	dev->slab_netmsg_data = kmem_cache_create("vmem_netmsg_data",
				sizeof(struct netmsg_data), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_netmsg_data) {
		KER_DEBUG(KERN_NOTICE"vmem:create vmem_serhost slab fail\n");
		goto err_netmsg_data_slab;
	}
	//init mutex
	mutex_init(&dev->lshd_serhost_mutex);
	mutex_init(&dev->lshd_read_mutex);
	KER_DEBUG(KERN_NOTICE"vmem:vmem_create\n");

	//init block table
	memset(blktable, 0, sizeof(blktable));
	for(nIndex = 0; nIndex < BLK_NUM_MAX; nIndex++) {
		mutex_init(&blktable[nIndex].handle_mutex);
		blktable[nIndex].inuse_page = 0;
	}
	dev->addr_entry = blktable;
	//init vpage alloc
	memset(&vpage_alloc, 0 ,sizeof(struct vpage_alloc));
	mutex_init(&vpage_alloc.access_mutex);
	dev->vpage_alloc = &vpage_alloc;
	//init daemon thread
	dev->DaemonThread = kthread_create(vmem_daemon, (void *)dev, "vmem daemon");
	wake_up_process(dev->DaemonThread);
	return ret;

	kmem_cache_destroy(dev->slab_netmsg_data);
err_netmsg_data_slab:
	kmem_cache_destroy(dev->slab_netmsg_req);
err_netmsg_req_slab:
	kmem_cache_destroy(dev->slab_server_host);
err_serhost_slab:
err_sysfs_create:
err_create_device:
	return ret;
}

static int __init vmem_init(void) {
	int result;
	dev_t devno;

	//register devices
	devno = MKDEV(vmem_major, 0);
	if(vmem_major) {
		result = register_chrdev_region(devno, 1, VMEM_NAME);
	}
	else {
		result = alloc_chrdev_region(&devno, 0, 1, VMEM_NAME);
		vmem_major = MAJOR(devno);
		vmem_minor = MINOR(devno);
	}
	if(vmem_major <= 0) {
		KER_DEBUG(KERN_WARNING"vmem:%s: unable to get major number\n", VMEM_NAME);
		return -EBUSY;
	}
	Devices = (struct vmem_dev *)kmalloc(sizeof(struct vmem_dev), GFP_KERNEL);
	if(Devices == NULL) {
		goto out_unregister;
	}

	setup_device(Devices, devno);
	KER_DEBUG(KERN_NOTICE"vmem:vmem_init\n");
	return 0;

out_unregister:
	unregister_blkdev(vmem_major, VMEM_NAME);
	return -ENOMEM;
}

static void vmem_exit(void) {
	destory_device(Devices, 0);
	unregister_chrdev_region(MKDEV(vmem_major, 0), 1);
	kfree(Devices);
	KER_DEBUG(KERN_NOTICE"vmem:vmem_exit\n");
}

module_init(vmem_init);
module_exit(vmem_exit);

MODULE_AUTHOR("VincentGuo");
MODULE_LICENSE("GPL");
