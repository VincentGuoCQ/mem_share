#ifndef	COMMON_H
#define COMMON_H

#include <linux/module.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fcntl.h>
#include <linux/vmalloc.h>
#include <linux/hdreg.h>
#include <linux/blkpg.h>
#include <linux/timer.h>
#include <linux/bio.h>
#include <linux/socket.h>
#include <linux/list.h>
#include <linux/in.h>

#define VMEM_NAME				"vmem"
#define MEMPOOL_NAME			"mempool"
#define INVALIDATE_DELAY		30*HZ
#define KERNEL_SECTOR_SIZE		512

#define VPAGE_SIZE_SHIFT	10
#define VPAGE_SIZE			(1UL << VPAGE_SIZE_SHIFT)
#define BLK_SIZE_SHIFT		13
#define BLK_SIZE			(1UL << BLK_SIZE_SHIFT)
#define BLK_NUM_MAX_SHIFT	3
#define BLK_NUM_MAX		(1UL << BLK_NUM_MAX_SHIFT)

#define VPAGE_NUM_IN_BLK	(1UL << (BLK_SIZE_SHIFT - VPAGE_SIZE_SHIFT))

#define HOST_NAME_LEN		32
#define IP_ADDR_LEN			16

#define MAX_BLK_NUM_IN_MEMPOOL	(1UL << 2)

#ifdef VMEM
static int vmem_major = 0;
static int vmem_minor= 1;

module_param(vmem_major, int, 0);
module_param(vmem_minor, int, 0);
#endif

#ifdef MEMPOOL
static int mempool_major = 0;
static int mempool_minor= 1;

module_param(mempool_major, int, 0);
module_param(mempool_minor, int, 0);
#endif

static unsigned int hardsect_size = VPAGE_SIZE;
static unsigned int nsectors = (1UL << (BLK_SIZE_SHIFT - VPAGE_SIZE_SHIFT));
static unsigned int ndevices = 1;

module_param(hardsect_size, int, 0);
module_param(nsectors, int, 0);
module_param(ndevices, int, 0);


#define RM_SIMPLE 0
#define	RM_FULL 1
#define	RM_NOQUEUE 2

static int request_mode = RM_SIMPLE;
module_param(request_mode, int, RM_SIMPLE);

#define IPPROTOL_VMEM 200

#define TRUE	1
#define FALSE	0

#ifdef MEMPOOL

struct mempool_blk {
	bool avail:1;
	bool inuse:1;
	void *blk_addr;
	struct page * blk_pages;
};

struct client_host {
	struct list_head ls_rent;
	struct mutex lshd_rent_client;
	char host_name[HOST_NAME_LEN];
	struct in_addr host_addr;
	unsigned int block_num; 
	unsigned int state;
};

struct mempool_dev {
	struct request_queue *queue;
	struct gendisk *gd;
	struct timer_list timer;
	spinlock_t lock;

	struct list_head lshd_rent_client;
	struct mutex lshd_rent_client_mutex;

	struct mempool_blk blk_info[MAX_BLK_NUM_IN_MEMPOOL];

	struct kmem_cache * slab_client_host;
};

#endif

#ifdef VMEM
struct server_host {
	struct list_head ls_available;
	struct list_head ls_inuse;
	char host_name[HOST_NAME_LEN];
	struct in_addr host_addr;
	unsigned int block_num; 
	unsigned int state;
};

struct vmem_blk {
	struct server_host sh_info;
	bool:1;
	bool inuse:1;
	unsigned long blk_start_pos;
	unsigned long blk_size;
};

#define ADDR_SPACE_LEN  BLK_NUM_MAX_SHIFT+BLK_SIZE_SHIFT

struct cli_blk {
	union {
		struct vmem_blk * vmem;
		struct native_blk {
			void *addr;
			struct page *pages;
		}native;
	} entry;
	bool:1;
	bool mapped:1;
	bool native:1;
	bool page_bitmap[VPAGE_NUM_IN_BLK];
};

struct vmem_dev {
	struct request_queue *queue;
	struct gendisk *gd;
	struct timer_list timer;
	spinlock_t lock;
	int user;
	unsigned int size;
	char * data;
	int media_change;
	struct list_head lshd_available;
	struct mutex lshd_avail_mutex;
	struct list_head lshd_inuse;
	struct mutex lshd_inuse_mutex;
	struct kmem_cache * slab_server_host;
	struct cli_blk * addr_entry;
};

#endif


int create_sysfs_file(struct device *dev);
void delete_sysfs_file(struct device *dev);

#endif // COMMON_H
