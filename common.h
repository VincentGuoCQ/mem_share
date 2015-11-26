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
#include <linux/kthread.h>

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/types.h>
#include <asm/unaligned.h>

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

#define MAX_BLK_NUM_IN_MEMPOOL	(1UL << 3)

#define SERHOST_LISTEN_PORT	8000

#define SCHEDULE_TIME	0.5

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

#define LISTEM_MAX_QUEUE 5
#define MEMPOOL_IF_NAME "eth0"
struct mempool_blk {
	bool avail:1;
	bool inuse:1;
	struct client_host * clihost;
	void *blk_addr;
	struct page * blk_pages;
};

#define CLIHOST_STATE_CONNECTED 1
#define CLIHOST_STATE_CLOSED 2

struct client_host {
	struct list_head ls_rent;
	char host_name[HOST_NAME_LEN];
	struct sockaddr_in host_addr;
	unsigned int block_num; 
	unsigned int state;
	struct socket *sock;
	struct task_struct *CliRecvThread;
	struct task_struct *CliSendThread;

	struct mutex ptr_mutex;

	struct mutex lshd_req_msg_mutex;
	struct list_head lshd_req_msg;
	struct mutex lshd_rpy_msg_mutex;
	struct list_head lshd_rpy_msg;

	struct kmem_cache * slab_netmsg_req;
	struct kmem_cache * slab_netmsg_rpy;
};

#define MEMPOOL_STATE_LISTEN 1
#define MEMPOOL_STATE_CLOSED 2

struct mempool_dev {
	struct request_queue *queue;
	struct gendisk *gd;
	struct timer_list timer;
	spinlock_t lock;

	struct list_head lshd_rent_client;
	struct mutex lshd_rent_client_mutex;

	struct mempool_blk blk[MAX_BLK_NUM_IN_MEMPOOL];
	struct mutex blk_mutex;

	struct kmem_cache * slab_client_host;

	struct socket * listen_sock;
	struct task_struct *ListenThread;

	struct kmem_cache * slab_netmsg_req;
	struct kmem_cache * slab_netmsg_rpy;
};

#endif

#ifdef VMEM

//the period for re-calculate the precent of free pages, in seconds
#define CALCULATE_PERIOD 5
//the precentage for the daemon thread to trigger memory borrow
#define UPPER_LIMIT_PRECENT 0.8
//the precentage for the daemon thread to trigger memory return
#define LOWER_LIMIT_PRECENT 0.2

#define VMEM_IF_NAME "eth0"

struct server_host {
	struct list_head ls_available;
	struct list_head ls_inuse;
	char host_name[HOST_NAME_LEN];
	struct sockaddr_in host_addr;
	unsigned int block_inuse; 
	unsigned int block_available; 
	unsigned int state;
	struct task_struct *SerRecvThread;
	struct task_struct *SerSendThread;
	struct socket *sock;

	struct mutex ptr_mutex;

	struct mutex lshd_req_msg_mutex;
	struct list_head lshd_req_msg;
	struct mutex lshd_rpy_msg_mutex;
	struct list_head lshd_rpy_msg;

	struct kmem_cache *slab_netmsg_req;
	struct kmem_cache *slab_netmsg_rpy;
};

struct vmem_blk {
	struct server_host *serhost;
	bool:1;
	bool inuse:1;
	unsigned long blk_start_pos;
	unsigned long blk_size;
};

#define ADDR_SPACE_LEN  BLK_NUM_MAX_SHIFT+BLK_SIZE_SHIFT

struct cli_blk {
	struct mutex handle_mutex;
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
	unsigned int inuse_count;
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
	struct task_struct *DaemonThread;
	struct kmem_cache *slab_netmsg_req;
	struct kmem_cache *slab_netmsg_rpy;
};

int vmem_daemon(void *);

#endif

int mempool_listen_thread(void *data);
int create_sysfs_file(struct device *dev);
void delete_sysfs_file(struct device *dev);

#endif // COMMON_H
