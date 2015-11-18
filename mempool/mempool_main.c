#define MEMPOOL

#include "../common.h"
#include "userspace/errors.h"

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
	struct client_host *ps = NULL;
	int nIndex = 0;
	
	if(!dev) {
		return;
	}
	del_timer_sync(&dev->timer);
	//destory block
	for(nIndex = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL; nIndex++) {
		if(dev->blk_info[nIndex].avail) {
			kunmap(dev->blk_info[nIndex].blk_pages);
			__free_pages(dev->blk_info[nIndex].blk_pages, BLK_SIZE_SHIFT-PAGE_SHIFT);
			dev->blk_info[nIndex].avail = FALSE;
		}
	}
	//destroy list
	mutex_lock(&dev->lshd_rent_client_mutex);
	list_for_each_safe(p, next, &dev->lshd_rent_client) {
		ps = list_entry(p, struct client_host, ls_rent);
		list_del(&ps->ls_rent);
		kmem_cache_free(dev->slab_client_host, ps);
	}
	mutex_unlock(&dev->lshd_rent_client_mutex);
	//delete slab
	if(dev->slab_client_host) {
		kmem_cache_destroy(dev->slab_client_host);
	}

	//delete sysfs file
	delete_sysfs_file(disk_to_dev(dev->gd));

	//delete gendisk
	if(dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}
}

static void setup_device(struct mempool_dev *dev, int which) {
	int err = 0;
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
				goto err_alloc;
			}
			blk_queue_make_request(dev->queue, mempool_make_request);
			break;
		default:
			printk(KERN_NOTICE"mempool:Bad request mode %d, using sample\n", request_mode);
		case RM_SIMPLE:
			dev->queue = blk_init_queue(mempool_request, &dev->lock);
			if(dev->queue == NULL) {
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
	err = create_sysfs_file(disk_to_dev(dev->gd));
	if(err == -ERR_VMEM_CREATE_FILE) {
		printk(KERN_NOTICE"mempool:create sysfs file fail\n");
		goto err_sysfs_create;
	}

	//create slab for client host
	dev->slab_client_host = kmem_cache_create("mempool_clihost", sizeof(struct client_host), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_client_host) {
		printk(KERN_NOTICE"mempool:create mempool_clihost slab fail\n");
		goto err_clihost_slab;
	}
	//init mutex
	mutex_init(&dev->lshd_rent_client_mutex);

	//init blk
	for(nIndex = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL; nIndex++) {
		dev->blk_info[nIndex].avail = FALSE;
		dev->blk_info[nIndex].blk_addr = NULL;
		dev->blk_info[nIndex].blk_pages = NULL;
	}
	printk(KERN_NOTICE"mempool:mempool_create\n");

	return;

err_clihost_slab:
err_sysfs_create:
err_alloc:
	return;
}

static int __init mempool_init(void) {
	int i;
	//register devices
	mempool_major = register_blkdev(mempool_major, VMEM_NAME);
	if(mempool_major <= 0) {
		printk(KERN_WARNING"mempool:%s: unable to get major number\n", VMEM_NAME);
		return -EBUSY;
	}
	Devices = (struct mempool_dev *)kmalloc(ndevices * sizeof(struct mempool_dev), GFP_KERNEL);
	if(Devices == NULL) {
		goto out_unregister;
	}

	for(i = 0; i < ndevices; i++) {
		setup_device(Devices + i, i);
	}
	printk(KERN_NOTICE"mempool:mempool_init\n");
	return 0;

out_unregister:
	unregister_blkdev(mempool_major, VMEM_NAME);
	return -ENOMEM;
}

static void mempool_exit(void) {
	int i;
	for(i = 0; i < ndevices; i++) {
		destory_device(Devices + i, i);
	}
	unregister_blkdev(mempool_major, VMEM_NAME);
	kfree(Devices);
	printk(KERN_NOTICE"mempool:mempool_exit\n");
}

module_init(mempool_init);
module_exit(mempool_exit);

MODULE_AUTHOR("gpf");
MODULE_LICENSE("GPL");
