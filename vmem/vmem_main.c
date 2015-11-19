#define VMEM

#include "../common.h"
#include "userspace/errors.h"

struct vmem_dev *Devices = NULL;
struct cli_blk blktable[BLK_NUM_MAX];

static int vmem_open(struct block_device *bdev, fmode_t mode) {
	struct vmem_dev * dev = bdev->bd_disk->private_data;

	del_timer_sync(&dev->timer);
	spin_lock(&dev->lock);
	dev->user++;
	spin_unlock(&dev->lock);
	return 0;
}

static void vmem_release(struct gendisk *disk, fmode_t mode) {
	struct vmem_dev *dev = disk->private_data;
	spin_lock(&dev->lock);
	dev->user--;
	if(!dev->user) {
		dev->timer.expires = jiffies + INVALIDATE_DELAY;
		add_timer(&dev->timer);
	}
	spin_unlock(&dev->lock);
	return;
}
int vmem_media_changed(struct gendisk *gd) {
	struct vmem_dev *dev = gd->private_data;
	return dev->media_change;
}
int vmem_revalidate(struct gendisk *gd) {
	struct vmem_dev *dev = gd->private_data;
	if(dev->media_change) {
		dev->media_change = 0;
		memset(dev->data, 0, dev->size);
	}
	return 0;
}
void vmem_invalidate(unsigned long ldev) {
	struct vmem_dev *dev = (struct vmem_dev *)ldev;
	spin_lock(&dev->lock);
	if(dev->user || !dev->data) {
		printk(KERN_WARNING"vmem: timer sanity check failed\n");
	}
	else {
		dev->media_change = 1;
	}
	spin_unlock(&dev->lock);
}
static int vmem_getgeo(struct block_device *bdev, struct hd_geometry *geo) {
	long size;
	struct vmem_dev *dev = bdev->bd_disk->private_data;

	size = dev->size *(hardsect_size/KERNEL_SECTOR_SIZE);
	geo->cylinders = (size & ~0x3f) >> 6;
	geo->heads = 4;
	geo->sectors = 16;
	geo->start = 4;
	return 0;
}

static struct block_device_operations vmem_ops = {
	.owner = THIS_MODULE,
	.open = vmem_open,
	.release = vmem_release,
	.media_changed = vmem_media_changed,
	.revalidate_disk = vmem_revalidate,
	.getgeo = vmem_getgeo,
};

static void vmem_transfer(struct vmem_dev *dev, unsigned long sector, unsigned long nsect, char *buffer, int write) {
	unsigned long offset = sector * KERNEL_SECTOR_SIZE;
	unsigned long nbytes = nsect * KERNEL_SECTOR_SIZE;
	if((offset + nbytes) > dev->size) {
		printk(KERN_NOTICE"vmem:Beyond-end write (%ld %ld)\n", offset, nbytes);
		return;
	}
	if(write) {
		memcpy(dev->data+offset, buffer, nbytes);
	}
	else {
		memcpy(buffer, dev->data+offset, nbytes);
	}
}
static int vmem_xfer_bio(struct vmem_dev *dev, struct bio *bio) {
	struct bvec_iter iter;
	struct bio_vec bvec;
	sector_t sector = bio->bi_iter.bi_sector;

	bio_for_each_segment(bvec, bio, iter) {
		char * buffer = __bio_kmap_atomic(bio, iter);
		vmem_transfer(dev, sector, bio_cur_bytes(bio)>>9, buffer, bio_data_dir(bio)==WRITE);
		sector += bio_sectors(bio);
		__bio_kunmap_atomic(buffer);
	}
	return 0;
}
static void vmem_request(struct request_queue *q) {
	struct request *req;
	struct bio *bio;

	while((req =blk_peek_request(q)) != NULL) {
		struct vmem_dev *dev = req->rq_disk->private_data;
		if(req->cmd_type != REQ_TYPE_FS) {
			printk(KERN_NOTICE"vmem:skip non-fs request\n");
			blk_start_request(req);
			__blk_end_request_all(req, -EIO);
			continue;
		}
		blk_start_request(req);
		__rq_for_each_bio(bio, req)
			vmem_xfer_bio(dev, bio);
		__blk_end_request_all(req, 0);
	}
}
static void vmem_make_request(struct request_queue *q, struct bio *bio) {
	struct vmem_dev *dev = q->queuedata;
	int status;

	status = vmem_xfer_bio(dev, bio);
	bio_endio(bio, status);
	return;
}
static void destory_device(struct vmem_dev *dev, int which) {
	struct list_head *p = NULL, *next = NULL;
	struct server_host *ps = NULL;
	int nIndex = 0;
	
	if(!dev) {
		return;
	}
	del_timer_sync(&dev->timer);
	//destroy native block
	for(nIndex = 0; nIndex < BLK_NUM_MAX; nIndex++) {
		if(dev->addr_entry[nIndex].mapped && dev->addr_entry[nIndex].native) {
			kunmap(dev->addr_entry[nIndex].entry.native.pages);
			__free_pages(dev->addr_entry[nIndex].entry.native.pages, BLK_SIZE_SHIFT-PAGE_SHIFT);
			dev->addr_entry[nIndex].mapped = FALSE;
			dev->addr_entry[nIndex].native = FALSE;
		}
	}
	//destroy server host list
	mutex_lock(&dev->lshd_avail_mutex);
	list_for_each_safe(p, next, &dev->lshd_available) {
		ps = list_entry(p, struct server_host, ls_available);
		list_del(&ps->ls_available);
		kmem_cache_free(dev->slab_server_host, ps);
	}
	mutex_unlock(&dev->lshd_inuse_mutex);
	//delete slab
	if(dev->slab_server_host) {
		kmem_cache_destroy(dev->slab_server_host);
	}
	//delete sysfs file
	delete_sysfs_file(disk_to_dev(dev->gd));
	//delete gendisk
	if(dev->gd) {
		del_gendisk(dev->gd);
		put_disk(dev->gd);
	}
	//clean request queue
	if(dev->queue) {
		if(request_mode == RM_NOQUEUE) {
			kobject_put(&dev->queue->kobj);
		}
		else {
			blk_cleanup_queue(dev->queue);
		}
	}
	//free data memory space
	if(dev->data) {
		vfree(dev->data);
	}
}

static void setup_device(struct vmem_dev *dev, int which) {
	int err = 0;
	memset(dev, 0, sizeof(struct vmem_dev));

	INIT_LIST_HEAD(&dev->lshd_available);
	INIT_LIST_HEAD(&dev->lshd_inuse);

	//alloc data memory
	dev->size = nsectors*hardsect_size;
	dev->data = vmalloc(dev->size);
	if(dev->data == NULL) {
		printk(KERN_NOTICE"vmem:vmalloc failure\n");
		return;
	}

	spin_lock_init(&dev->lock);

	//timer init
	init_timer(&dev->timer);
	dev->timer.data = (unsigned long)dev;
	dev->timer.function = vmem_invalidate;
	//request queue init
	switch(request_mode) {
		case RM_NOQUEUE:
			dev->queue = blk_alloc_queue(GFP_KERNEL);
			if(dev->queue == NULL) {
				goto err_alloc;
			}
			blk_queue_make_request(dev->queue, vmem_make_request);
			break;
		default:
			printk(KERN_NOTICE"vmem:Bad request mode %d, using sample\n", request_mode);
		case RM_SIMPLE:
			dev->queue = blk_init_queue(vmem_request, &dev->lock);
			if(dev->queue == NULL) {
				goto err_alloc;
			}
			break;
	}

	blk_queue_logical_block_size(dev->queue, hardsect_size);
	dev->queue->queuedata = dev;
	
	//gendisk init		
	dev->gd = alloc_disk(vmem_minor);
	if(!dev->gd) {
		printk(KERN_NOTICE"vmem:alloc_disk failure");
		goto err_alloc;
	}

	dev->gd->major = vmem_major;
	dev->gd->first_minor = which*vmem_minor;
	dev->gd->fops = &vmem_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;

	snprintf(dev->gd->disk_name, DISK_NAME_LEN, VMEM_NAME);
	set_capacity(dev->gd, nsectors*(hardsect_size/KERNEL_SECTOR_SIZE));
	add_disk(dev->gd);

	//create sysfs file
	err = create_sysfs_file(disk_to_dev(dev->gd));
	if(err == -ERR_VMEM_CREATE_FILE) {
		printk(KERN_NOTICE"vmem:create sysfs file fail\n");
		goto err_sysfs_create;
	}

	//create slab for server host
	dev->slab_server_host = kmem_cache_create("vmem_serhost", sizeof(struct server_host), sizeof(long), SLAB_HWCACHE_ALIGN, NULL);
	if(NULL == dev->slab_server_host) {
		printk(KERN_NOTICE"vmem:create vmem_serhost slab fail\n");
		goto err_serhost_slab;
	}
	//init mutex
	mutex_init(&dev->lshd_avail_mutex);
	printk(KERN_NOTICE"vmem:vmem_create\n");

	//init block table
	memset(blktable, 0, sizeof(blktable));
	dev->addr_entry = blktable;
	return;

err_serhost_slab:
err_sysfs_create:
err_alloc:
	if(dev->data) {
		vfree(dev->data);
	}
	return;
}

static int __init vmem_init(void) {
	int i;
	//register devices
	vmem_major = register_blkdev(vmem_major, VMEM_NAME);
	if(vmem_major <= 0) {
		printk(KERN_WARNING"vmem:%s: unable to get major number\n", VMEM_NAME);
		return -EBUSY;
	}
	Devices = (struct vmem_dev *)kmalloc(ndevices * sizeof(struct vmem_dev), GFP_KERNEL);
	if(Devices == NULL) {
		goto out_unregister;
	}

	for(i = 0; i < ndevices; i++) {
		setup_device(Devices + i, i);
	}
	printk(KERN_NOTICE"vmem:vmem_init\n");
	return 0;

out_unregister:
	unregister_blkdev(vmem_major, VMEM_NAME);
	return -ENOMEM;
}

static void vmem_exit(void) {
	int i;
	for(i = 0; i < ndevices; i++) {
		destory_device(Devices + i, i);
	}
	unregister_blkdev(vmem_major, VMEM_NAME);
	kfree(Devices);
	printk(KERN_NOTICE"vmem:vmem_exit\n");
}

module_init(vmem_init);
module_exit(vmem_exit);

MODULE_AUTHOR("gpf");
MODULE_LICENSE("GPL");
