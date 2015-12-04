#include "../include.h"
#include "../kererr.h"
#include "../common.h"
#include "vmem_common.h"
#include "userspace/errors.h"
#include "../net_msg.h"

struct vmem_dev *Devices = NULL;
struct cli_blk blktable[BLK_NUM_MAX];
struct vpage_alloc vpage_alloc;
struct vpage_read vpage_read;

int vmem_open(struct inode *inode, struct file *filp) {
	filp->private_data = Devices;
	return 0;
}

int vmem_release(struct inode *inode, struct file *filp) {
	return 0;
}

static ssize_t vmem_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos) {
	int ret = 0;
	struct vmem_dev *dev =filp->private_data;
	return ret;
}

static ssize_t vmem_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos) {
	int ret = 0;
	struct vmem_dev *dev =filp->private_data;
	return ret;
}

static loff_t vmem_llseek(struct file *filp, loff_t offset, int orig) {
	loff_t ret = 0;
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

	if(!dev) {
		return;
	}
	//kill daemon thread
	if(dev->DaemonThread) {
		kthread_stop(dev->DaemonThread);
	}
	printk(KERN_INFO"vmem:destory daemon thread\n");
	//destroy native block
	for(nIndex = 0; nIndex < BLK_NUM_MAX; nIndex++) {
		if(dev->addr_entry[nIndex].inuse && dev->addr_entry[nIndex].native) {
			kunmap(dev->addr_entry[nIndex].entry.native.pages);
			__free_pages(dev->addr_entry[nIndex].entry.native.pages, BLK_SIZE_SHIFT-PAGE_SHIFT);
			dev->addr_entry[nIndex].inuse = FALSE;
			dev->addr_entry[nIndex].native = FALSE;
		}
	}
	printk(KERN_INFO"vmem:destory native block\n");
	//destory server host avail list
	mutex_lock(&dev->lshd_avail_mutex);
	list_for_each_safe(p, next, &dev->lshd_available) {
		pserhost = list_entry(p, struct server_host, ls_available);
		list_del(&pserhost->ls_available);
		kmem_cache_free(dev->slab_server_host, pserhost);
	}
	mutex_unlock(&dev->lshd_avail_mutex);
	printk(KERN_INFO"vmem:destory serverhost avail list\n");

	//destory server host inuse list 
	mutex_lock(&dev->lshd_inuse_mutex);
	list_for_each_safe(p, next, &dev->lshd_inuse) {
		struct list_head *sp = NULL, *snext = NULL;
		struct netmsg_req *netmsg_req = NULL;
		pserhost = list_entry(p, struct server_host, ls_inuse);

		mutex_lock(&pserhost->ptr_mutex);
		if(pserhost->sock) {
			sock_release(pserhost->sock);
			pserhost->sock = NULL;
		}
		mutex_unlock(&pserhost->ptr_mutex);
		printk(KERN_INFO"vmem:destory serverhost inuse sock\n");

		if(pserhost->SerSendThread) {
			kthread_stop(pserhost->SerSendThread);
			pserhost->SerSendThread = NULL;
		}
		printk(KERN_INFO"vmem:destory serverhost inuse send thread\n");

		if(pserhost->SerRecvThread) {
			kthread_stop(pserhost->SerRecvThread);
			pserhost->SerRecvThread = NULL;
		}
		printk(KERN_INFO"vmem:destory serverhost inuse recv thread\n");

		mutex_lock(&pserhost->lshd_req_msg_mutex);
		list_for_each_safe(sp, snext, &pserhost->lshd_req_msg) {
			netmsg_req = list_entry(sp, struct netmsg_req, ls_reqmsg);
			list_del(&netmsg_req->ls_reqmsg);
			kmem_cache_free(pserhost->slab_netmsg_req, netmsg_req);
		}
		mutex_unlock(&pserhost->lshd_req_msg_mutex);

		list_del(&pserhost->ls_inuse);
		kmem_cache_free(dev->slab_server_host, pserhost);
	}
	mutex_unlock(&dev->lshd_inuse_mutex);
	printk(KERN_INFO"vmem:destory serverhost inuse list\n");
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
	INIT_LIST_HEAD(&dev->lshd_available);
	INIT_LIST_HEAD(&dev->lshd_inuse);

	dev->devno = devno;
	//init dev	
	cdev_init(&dev->gd, &vmem_fops);
	dev->gd.owner = THIS_MODULE;
	ret = cdev_add(&dev->gd, dev->devno, 1);
	if(ret) {
		printk(KERN_NOTICE"Error %d adding vmem\n", ret);
		ret = KERERR_CREATE_DEVICE;
		goto err_create_device;
	}
	//create sysfs dir
	dev->vmem_class = class_create(THIS_MODULE, VMEM_NAME);
	dev->dev = device_create(dev->vmem_class, NULL, dev->devno, NULL, VMEM_NAME);
	//create sysfs file
	ret = create_sysfs_file(dev->dev);
	if(ret == KERERR_CREATE_FILE) {
		printk(KERN_NOTICE"vmem:create sysfs file fail\n");
		goto err_sysfs_create;
	}

	//create slab for server host
	dev->slab_server_host = kmem_cache_create("vmem_serhost",
				sizeof(struct server_host), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_server_host) {
		printk(KERN_NOTICE"vmem:create vmem_serhost slab fail\n");
		goto err_serhost_slab;
	}
	dev->slab_netmsg_req = kmem_cache_create("vmem_netmsg_req",
				sizeof(struct netmsg_req), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_netmsg_req) {
		printk(KERN_NOTICE"vmem:create vmem_serhost slab fail\n");
		goto err_netmsg_req_slab;
	}
	dev->slab_netmsg_data = kmem_cache_create("vmem_netmsg_data",
				sizeof(struct netmsg_data), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_netmsg_data) {
		printk(KERN_NOTICE"vmem:create vmem_serhost slab fail\n");
		goto err_netmsg_data_slab;
	}
	//init mutex
	mutex_init(&dev->lshd_avail_mutex);
	mutex_init(&dev->lshd_inuse_mutex);
	printk(KERN_NOTICE"vmem:vmem_create\n");

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
	//init vpage read
	memset(&vpage_read, 0 ,sizeof(struct vpage_read));
	mutex_init(&vpage_read.access_mutex);
	dev->vpage_read = &vpage_read;
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
		printk(KERN_WARNING"vmem:%s: unable to get major number\n", VMEM_NAME);
		return -EBUSY;
	}
	Devices = (struct vmem_dev *)kmalloc(ndevices * sizeof(struct vmem_dev), GFP_KERNEL);
	if(Devices == NULL) {
		goto out_unregister;
	}

	setup_device(Devices, devno);
	printk(KERN_NOTICE"vmem:vmem_init\n");
	return 0;

out_unregister:
	unregister_blkdev(vmem_major, VMEM_NAME);
	return -ENOMEM;
}

static void vmem_exit(void) {
	destory_device(Devices, 0);
	unregister_chrdev_region(MKDEV(vmem_major, 0), 1);
	kfree(Devices);
	printk(KERN_NOTICE"vmem:vmem_exit\n");
}

module_init(vmem_init);
module_exit(vmem_exit);

MODULE_AUTHOR("gpf");
MODULE_LICENSE("GPL");
