#include "../include.h"
#include "../common.h"
#include "../common.h"
#include "mempool_common.h"
#include "../kererr.h"
#include "userspace/errors.h"
#include "../net_msg.h"

struct mempool_dev *Devices = NULL;

//const struct inet_protos vmem_protocol = {
//	.early_demux = vmem_early_demux, 
//	.hander		= vmem_rx,
//	.err_hander = vmem_err,
//	.no_policy	= 1,
//	.netns_ok	= 1,
//};

static int mempool_open(struct block_device *bdev, fmode_t mode) {
	return 0;
}

static void mempool_release(struct gendisk *disk, fmode_t mode) {
	return;
}
int mempool_media_changed(struct gendisk *gd) {
	return 0;
}
int mempool_revalidate(struct gendisk *gd) {
	return 0;
}
void mempool_invalidate(unsigned long ldev) {
	return;
}
static int mempool_getgeo(struct block_device *bdev, struct hd_geometry *geo) {
	return 0;
}

static struct block_device_operations mempool_ops = {
	.owner = THIS_MODULE,
	.open = mempool_open,
	.release = mempool_release,
	.media_changed = mempool_media_changed,
	.revalidate_disk = mempool_revalidate,
	.getgeo = mempool_getgeo,
};

//static void mempool_transfer(struct mempool_dev *dev, unsigned long sector, unsigned long nsect, char *buffer, int write) {
//	return;
//}
//static int mempool_xfer_bio(struct mempool_dev *dev, struct bio *bio) {
//	return 0;
//}
static void mempool_request(struct request_queue *q) {
	return;
}
static void mempool_make_request(struct request_queue *q, struct bio *bio) {
	return;
}
static void destory_device(struct mempool_dev *dev, int which) {
	struct list_head *p = NULL, *next = NULL;
	struct client_host *clihost = NULL;
	int nIndex = 0;
	
	if(!dev) {
		return;
	}
	del_timer_sync(&dev->timer);
	
	//destory block
	for(nIndex = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL; nIndex++) {
		if(dev->blk[nIndex].avail) {
			kunmap(dev->blk[nIndex].blk_pages);
			__free_pages(dev->blk[nIndex].blk_pages, BLK_SIZE_SHIFT-PAGE_SHIFT);
			dev->blk[nIndex].avail = FALSE;
		}
	}
	printk(KERN_INFO"mempool:destory block\n");
	//destroy client list
	mutex_lock(&dev->lshd_rent_client_mutex);
	list_for_each_safe(p, next, &dev->lshd_rent_client) {
		struct list_head *sp = NULL, *snext = NULL;
		struct netmsg_req *netmsg_req = NULL;
		struct netmsg_data *netmsg_wrdata = NULL;
		clihost = list_entry(p, struct client_host, ls_rent);

		mutex_lock(&clihost->ptr_mutex);
		if(clihost->state == CLIHOST_STATE_CONNECTED) {
			clihost->state = CLIHOST_STATE_CLOSED;
			sock_release(clihost->sock);
			//clihost->sock = NULL;
		}
		mutex_unlock(&clihost->ptr_mutex);
		printk(KERN_INFO"mempool:destory clienthost sock\n");

		if(clihost->CliRecvThread) {
			kthread_stop(clihost->CliRecvThread);
			clihost->CliRecvThread = NULL;
		}
		printk(KERN_INFO"mempool:destory clienthost recv thread\n");

		if(clihost->CliSendThread) {
			kthread_stop(clihost->CliSendThread);
			clihost->CliSendThread = NULL;
		}
		printk(KERN_INFO"mempool:destory clienthost send thread\n");

		mutex_lock(&clihost->lshd_req_msg_mutex);
		list_for_each_safe(sp, snext, &clihost->lshd_req_msg) {
			netmsg_req = list_entry(sp, struct netmsg_req, ls_reqmsg);
			list_del(&netmsg_req->ls_reqmsg);
			kmem_cache_free(clihost->slab_netmsg_req, netmsg_req);
		}
		mutex_unlock(&clihost->lshd_req_msg_mutex);
		printk(KERN_INFO"mempool:destory clienthost req msg\n");

		mutex_lock(&clihost->lshd_wrdata_mutex);
		list_for_each_safe(sp, snext, &clihost->lshd_wrdata) {
			netmsg_wrdata = list_entry(sp, struct netmsg_data, ls_req);
			list_del(&netmsg_wrdata->ls_req);
			kmem_cache_free(clihost->slab_netmsg_data, netmsg_wrdata);
		}
		mutex_unlock(&clihost->lshd_wrdata_mutex);
		printk(KERN_INFO"mempool:destory clienthost wrdata msg\n");

		list_del(&clihost->ls_rent);
		kmem_cache_free(dev->slab_client_host, clihost);
	}
	mutex_unlock(&dev->lshd_rent_client_mutex);
	printk(KERN_INFO"mempool:destory client list\n");

	//delete client, netmsg slab
	if(dev->slab_client_host) {
		kmem_cache_destroy(dev->slab_client_host);
	}
	if(dev->slab_netmsg_req) {
		kmem_cache_destroy(dev->slab_netmsg_req);
	}
	if(dev->slab_netmsg_data) {
		kmem_cache_destroy(dev->slab_netmsg_data);
	}
	printk(KERN_INFO"mempool:destory client slab\n");
	//destory listen socket thread
	if(dev->listen_sock) {
		sock_release(dev->listen_sock);
		dev->listen_sock = NULL;
	}
	printk(KERN_INFO"mempool:destory listen thread\n");
	if(dev->ListenThread) {
		kthread_stop(dev->ListenThread);
		dev->ListenThread = NULL;
	}
	//delete sysfs file
	delete_sysfs_file(disk_to_dev(dev->gd));
	printk(KERN_INFO"mempool:destory sys file\n");
	//delete gendisk
	if(dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}
}

static int setup_device(struct mempool_dev *dev, int which) {
	int ret = KERERR_SUCCESS;
	int nIndex = 0;
	memset(dev, 0, sizeof(struct mempool_dev));

	INIT_LIST_HEAD(&dev->lshd_rent_client);

	spin_lock_init(&dev->lock);

	//timer init
	init_timer(&dev->timer);
	dev->timer.data = (unsigned long)dev;
	dev->timer.function = mempool_invalidate;

	//request queue init
	switch(request_mode) {
		case RM_NOQUEUE:
			dev->queue = blk_alloc_queue(GFP_KERNEL);
			if(dev->queue == NULL) {
				ret = KERERR_ALLOC;
				goto err_alloc;
			}
			blk_queue_make_request(dev->queue, mempool_make_request);
			break;
		default:
			printk(KERN_NOTICE"mempool:Bad request mode %d, using sample\n", request_mode);
		case RM_SIMPLE:
			dev->queue = blk_init_queue(mempool_request, &dev->lock);
			if(dev->queue == NULL) {
				ret = KERERR_ALLOC;
				goto err_alloc;
			}
			break;
	}

	blk_queue_logical_block_size(dev->queue, hardsect_size);
	dev->queue->queuedata = dev;

	//gendisk init		
	dev->gd = alloc_disk(mempool_minor);
	if(!dev->gd) {
		printk(KERN_NOTICE"mempool:alloc_disk failure");
		ret = KERERR_ALLOC;
		goto err_alloc;
	}

	dev->gd->major = mempool_major;
	dev->gd->first_minor = which*mempool_minor;
	dev->gd->fops = &mempool_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;

	snprintf(dev->gd->disk_name, DISK_NAME_LEN, MEMPOOL_NAME);
	set_capacity(dev->gd, 0);
	add_disk(dev->gd);

	//create sysfs file
	ret = create_sysfs_file(disk_to_dev(dev->gd));
	if(ret == ERR_VMEM_CREATE_FILE) {
		printk(KERN_NOTICE"mempool:create sysfs file fail\n");
		ret = KERERR_CREATE_FILE;
		goto err_sysfs_create;
	}

	//create slab for client host
	dev->slab_client_host = kmem_cache_create("mempool_clihost",
				sizeof(struct client_host), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_client_host) {
		printk(KERN_NOTICE"mempool:create mempool_clihost slab fail\n");
		ret = KERERR_CREATE_SLAB;
		goto err_clihost_slab;
	}
	dev->slab_netmsg_req = kmem_cache_create("mempool_netmsg_req",
				sizeof(struct netmsg_req), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_netmsg_req) {
		printk(KERN_NOTICE"mempool:create mempool_clihost slab fail\n");
		ret = KERERR_CREATE_SLAB;
		goto err_netmsg_req_slab;
	}
	dev->slab_netmsg_data = kmem_cache_create("mempool_netmsg_data",
				sizeof(struct netmsg_data), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_netmsg_data) {
		printk(KERN_NOTICE"mempool:create mempool_clihost slab fail\n");
		ret = KERERR_CREATE_SLAB;
		goto err_netmsg_data_slab;
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
		printk(KERN_ALERT "create recvmsg thread err, err=%ld\n", PTR_ERR(dev->ListenThread));
		ret = KERERR_CREATE_THREAD;
		goto err_create_thread;
	}
	wake_up_process(dev->ListenThread);
	printk(KERN_NOTICE"mempool:mempool_create\n");

	return ret;
err_create_thread:
	kmem_cache_destroy(dev->slab_netmsg_data);
err_netmsg_data_slab:
	kmem_cache_destroy(dev->slab_netmsg_req);
err_netmsg_req_slab:
	kmem_cache_destroy(dev->slab_client_host);
err_clihost_slab:
err_sysfs_create:
err_alloc:
	return ret;
}

static int __init mempool_init(void) {
	int ret = KERERR_SUCCESS;
	//register devices
	mempool_major = register_blkdev(mempool_major, VMEM_NAME);
	if(mempool_major <= 0) {
		printk(KERN_INFO"mempool:%s: unable to get major number\n", VMEM_NAME);
		return -EBUSY;
	}
	Devices = (struct mempool_dev *)kmalloc(ndevices * sizeof(struct mempool_dev), GFP_KERNEL);
	if(Devices == NULL) {
		goto err_kmalloc_dev;
	}

	ret = setup_device(Devices, 0);
	if(ret < KERERR_SUCCESS) {
		printk(KERN_INFO"mempool: create dev fail\n");
		goto err_setup_dev;
	}
	printk(KERN_NOTICE"mempool:mempool_init\n");
	return 0;

err_setup_dev:
err_kmalloc_dev:
	unregister_blkdev(mempool_major, VMEM_NAME);
	return -ENOMEM;
}

static void mempool_exit(void) {
	destory_device(Devices, 0);
	unregister_blkdev(mempool_major, VMEM_NAME);
	kfree(Devices);
	printk(KERN_NOTICE"mempool:mempool_exit\n");
}

module_init(mempool_init);
module_exit(mempool_exit);

MODULE_AUTHOR("gpf");
MODULE_LICENSE("GPL");
