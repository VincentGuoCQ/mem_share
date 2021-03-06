#include "../include.h"
#include "../common.h"
#include "../common.h"
#include "mempool_common.h"
#include "../kererr.h"
#include "userspace/errors.h"
#include "../net_msg.h"

struct mempool_dev *Devices = NULL;

int mempool_open(struct inode *inode, struct file *filp) {
	filp->private_data = Devices;
	return 0;
}

int mempool_release(struct inode *inode, struct file *filp) {
	return 0;
}

static ssize_t mempool_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos) {
	int ret = 0;
	//struct mempool_dev *dev =filp->private_data;
	return ret;
}

static ssize_t mempool_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos) {
	int ret = 0;
	//struct mempool_dev *dev =filp->private_data;
	return ret;
}

static loff_t mempool_llseek(struct file *filp, loff_t offset, int orig) {
	return 0;
}

static const struct file_operations mempool_fops = {
	.owner = THIS_MODULE,
	.llseek = mempool_llseek,
	.read = mempool_read,
	.write = mempool_write,
	.open = mempool_open,
	.release = mempool_release,
};

static void destory_device(struct mempool_dev *dev, int which) {
	struct list_head *p = NULL, *next = NULL;
	struct client_host *clihost = NULL;
	int nIndex = 0;
	
	if(!dev) {
		return;
	}

	//destory block
	for(nIndex = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL; nIndex++) {
		if(dev->blk[nIndex].avail) {
			kunmap(dev->blk[nIndex].blk_pages);
			__free_pages(dev->blk[nIndex].blk_pages, BLK_SIZE_SHIFT-PAGE_SHIFT);
			dev->blk[nIndex].avail = FALSE;
		}
	}
	KER_DEBUG(KERN_INFO"mempool:destory block\n");
	//destroy client list
	mutex_lock(&dev->lshd_rent_client_mutex);
	list_for_each_safe(p, next, &dev->lshd_rent_client) {
		clihost = list_entry(p, struct client_host, ls_rent);

		mutex_lock(&clihost->ptr_mutex);
		if(clihost->state == CLIHOST_STATE_CONNECTED) {
			clihost->state = CLIHOST_STATE_CLOSED;
			sock_release(clihost->sock);
			sock_release(clihost->datasock);
			//clihost->sock = NULL;
		}
		mutex_unlock(&clihost->ptr_mutex);
		KER_DEBUG(KERN_INFO"mempool:destory clienthost sock\n");

		if(clihost->CliHandleThread) {
			kthread_stop(clihost->CliHandleThread);
			clihost->CliHandleThread = NULL;
		}
		KER_DEBUG(KERN_INFO"mempool:destory clienthost handle thread\n");

		list_del(&clihost->ls_rent);
		kmem_cache_free(dev->slab_client_host, clihost);
	}
	mutex_unlock(&dev->lshd_rent_client_mutex);
	KER_DEBUG(KERN_INFO"mempool:destory client list\n");

	//delete client, netmsg slab
	if(dev->slab_client_host) {
		kmem_cache_destroy(dev->slab_client_host);
	}
	KER_DEBUG(KERN_INFO"mempool:destory client slab\n");
	//destory data listen socket
	if(dev->data_listen_sock) {
		sock_release(dev->data_listen_sock);
		dev->data_listen_sock = NULL;
	}
	//destory listen socket thread
	if(dev->listen_sock) {
		sock_release(dev->listen_sock);
		dev->listen_sock = NULL;
	}
	KER_DEBUG(KERN_INFO"mempool:destory listen thread\n");
	if(dev->ListenThread) {
		kthread_stop(dev->ListenThread);
		dev->ListenThread = NULL;
	}
	//delete sysfs file
	delete_sysfs_file(dev->dev);
	KER_DEBUG(KERN_INFO"mempool:destory sys file\n");
	//delete dev
	cdev_del(&dev->gd);
	//delete sysfs dir
	device_destroy(dev->mempool_class, dev->devno);
	class_destroy(dev->mempool_class);
}

static int setup_device(struct mempool_dev *dev, dev_t devno) {
	int ret = KERERR_SUCCESS;
	int nIndex = 0;
	int err;

	memset(dev, 0, sizeof(struct mempool_dev));

	dev->devno = devno;

	INIT_LIST_HEAD(&dev->lshd_rent_client);
	//init dev
	cdev_init(&dev->gd, &mempool_fops);
	dev->gd.owner = THIS_MODULE;
	err = cdev_add(&dev->gd, dev->devno, 1);
	if(err) {
		KER_DEBUG(KERN_NOTICE "Error %d adding mempool\n", err);
		ret = KERERR_CREATE_DEVICE;
		goto err_create_device;
	}
	//create sysfs dir
	dev->mempool_class = class_create(THIS_MODULE, MEMPOOL_NAME);
	dev->dev = device_create(dev->mempool_class, NULL, dev->devno, NULL, MEMPOOL_NAME);
	//create sysfs file
	ret = create_sysfs_file(dev->dev);
	if(ret == KERERR_CREATE_FILE) {
		KER_DEBUG(KERN_NOTICE"mempool:create sysfs file fail\n");
		ret = KERERR_CREATE_FILE;
		goto err_sysfs_create;
	}

	//create slab for client host
	dev->slab_client_host = kmem_cache_create("mempool_clihost",
				sizeof(struct client_host), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_client_host) {
		KER_DEBUG(KERN_NOTICE"mempool:create mempool_clihost slab fail\n");
		ret = KERERR_CREATE_SLAB;
		goto err_clihost_slab;
	}
	//init mutex
	mutex_init(&dev->lshd_rent_client_mutex);
	mutex_init(&dev->blk_mutex);

	//init blk
	for(nIndex = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL; nIndex++) {
		dev->blk[nIndex].avail = FALSE;
		dev->blk[nIndex].blk_addr = NULL;
		dev->blk[nIndex].blk_pages = NULL;
		dev->blk[nIndex].clihost = NULL;
	}
	//create listen socket thread
	dev->ListenThread = kthread_create(mempool_listen_thread, (void *)dev, "mempool listen daemon");
	if (IS_ERR(dev->ListenThread)) {
		KER_DEBUG(KERN_ALERT "create thread err, err=%ld\n", PTR_ERR(dev->ListenThread));
		ret = KERERR_CREATE_THREAD;
		goto err_create_thread;
	}
	wake_up_process(dev->ListenThread);
	KER_DEBUG(KERN_NOTICE"mempool:mempool_create\n");

	return ret;
err_create_thread:
	kmem_cache_destroy(dev->slab_client_host);
err_clihost_slab:
err_sysfs_create:
err_create_device:
	return ret;
}

static int __init mempool_init(void) {
	int ret = KERERR_SUCCESS;
	dev_t devno;
	//register devices
	devno = MKDEV(mempool_major, 0);
	if(mempool_major) {
		ret = register_chrdev_region(devno, 1, MEMPOOL_NAME);
	}
	else {
		ret = alloc_chrdev_region(&devno, 0, 1, MEMPOOL_NAME);
		mempool_major = MAJOR(devno);
		mempool_minor = MINOR(devno);
	}
	if(mempool_major <= 0) {
		KER_DEBUG(KERN_INFO"mempool:%s: unable to get major number\n", MEMPOOL_NAME);
		return -EBUSY;
	}

	Devices = (struct mempool_dev *)kmalloc(sizeof(struct mempool_dev), GFP_KERNEL);
	if(Devices == NULL) {
		goto err_kmalloc_dev;
	}
	ret = setup_device(Devices, devno);
	if(ret < KERERR_SUCCESS) {
		KER_DEBUG(KERN_INFO"mempool: create dev fail\n");
		goto err_setup_dev;
	}
	KER_DEBUG(KERN_NOTICE"mempool:mempool_init\n");
	return 0;

err_setup_dev:
err_kmalloc_dev:
	unregister_chrdev_region(devno, 1);
	return -ENOMEM;
}

static void mempool_exit(void) {
	destory_device(Devices, 0);
	unregister_chrdev_region(MKDEV(mempool_major, 0), 1);
	kfree(Devices);
	KER_DEBUG(KERN_NOTICE"mempool:mempool_exit\n");
}

module_init(mempool_init);
module_exit(mempool_exit);

MODULE_AUTHOR("VincentGuo");
MODULE_LICENSE("GPL");
