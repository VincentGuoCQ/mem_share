#ifndef	VMEM_COMMON_H
#define VMEM_COMMON_H

static int vmem_major = 0;
static int vmem_minor= 0;

module_param(vmem_major, int, 0);
module_param(vmem_minor, int, 0);

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
	struct mutex lshd_wrdata_mutex;
	struct list_head lshd_wrdata;

	struct kmem_cache *slab_netmsg_req;
	struct kmem_cache *slab_netmsg_data;
};

struct vmem_blk {
	struct server_host *serhost;
	bool:1;
	bool inuse:1;
	unsigned int blk_remote_index;
	unsigned long blk_remote_addr;
	unsigned long blk_size;
};

struct cli_blk {
	struct mutex handle_mutex;
	union {
		struct vmem_blk vmem;
		struct native_blk {
			void *addr;
			struct page *pages;
		}native;
	} entry;
	bool:1;
	bool remote:1;
	bool inuse:1;
	bool native:1;
	bool page_bitmap[VPAGE_NUM_IN_BLK];
	unsigned int inuse_page;
};

struct vpage_alloc {
	struct mutex access_mutex;
	unsigned int vpagenum;
	unsigned long vpageaddr[VPAGE_PER_ALLOC];
};
struct vpage_read {
	struct mutex access_mutex;
	unsigned long vpageaddr;
	char Data[VPAGE_SIZE];
};
struct vmem_dev {
	struct request_queue *queue;
	struct cdev gd;
	struct class *vmem_class;
	struct device *dev;
	dev_t devno;
	int user;
	unsigned int size;

	struct list_head lshd_available;
	struct mutex lshd_avail_mutex;
	struct list_head lshd_inuse;
	struct mutex lshd_inuse_mutex;

	struct kmem_cache * slab_server_host;
	struct cli_blk * addr_entry;
	struct task_struct *DaemonThread;

	struct kmem_cache *slab_netmsg_req;
	struct kmem_cache *slab_netmsg_data;

	struct vpage_alloc *vpage_alloc;
	struct vpage_read *vpage_read;
};

int vmem_daemon(void *);


int create_sysfs_file(struct device *dev);
void delete_sysfs_file(struct device *dev);

#endif // VMEM_COMMON_H
