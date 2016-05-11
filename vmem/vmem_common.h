#ifndef	VMEM_COMMON_H
#define VMEM_COMMON_H
//#define DEBUG

#ifdef DEBUG
#define KER_DEBUG(STR, args...)	printk(STR, ##args)
#else
#define KER_DEBUG(STR, args...)
#endif 

#define KER_PRT(STR, args...)	printk(STR, ##args)

#define SWAP_FILE "/root/swap.file"

static int vmem_major = 0;
static int vmem_minor= 0;

module_param(vmem_major, int, 0);
module_param(vmem_minor, int, 0);


//the period for re-calculate the precent of free pages, in seconds
#define CALCULATE_PERIOD 10
#define HEARTBEAT_PERIOD 5
//the precentage for the daemon thread to trigger memory borrow
#define UPPER_LIMIT_PRECENT 0.8
//the precentage for the daemon thread to trigger memory return
#define LOWER_LIMIT_PRECENT 0.2

#define VMEM_IF_NAME "eth0"

#define CLIHOST_STATE_CONNECTED 1
#define CLIHOST_STATE_CLOSED	2 

struct server_host {
	struct list_head ls_serhost;
	struct sockaddr_in host_addr;
	struct sockaddr_in host_data_addr;
	unsigned int block_inuse; 
	unsigned int block_available; 
	unsigned int state;
	struct task_struct *SerRecvThread;
	struct task_struct *SerSendThread;
	struct socket *sock;
	struct socket *datasock;

	struct mutex ptr_mutex;

	struct mutex lshd_req_msg_mutex;
	struct list_head lshd_req_msg;
	struct mutex lshd_wrdata_mutex;
	struct list_head lshd_wrdata;

	struct semaphore send_sem;

	struct kmem_cache *slab_netmsg_req;
	struct kmem_cache *slab_netmsg_data;
};

struct vmem_blk {
	struct server_host *serhost;
	bool:1;
	bool inuse:1;
	unsigned int blk_remote_index;
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

struct vmem_dev {
	struct request_queue *queue;
	struct cdev gd;
	struct class *vmem_class;
	struct device *dev;
	dev_t devno;
	int user;
	unsigned int size;

	struct list_head lshd_serhost;
	struct mutex lshd_serhost_mutex;
	struct list_head lshd_read;
	struct mutex lshd_read_mutex;
	struct semaphore read_semphore;
	struct timer_list heartbeat;

	struct kmem_cache * slab_server_host;
	struct cli_blk * addr_entry;
	struct task_struct *DaemonThread;

	struct kmem_cache *slab_netmsg_req;
	struct kmem_cache *slab_netmsg_data;

	struct vpage_alloc *vpage_alloc;
};

int vmem_daemon(void *);


int create_sysfs_file(struct device *dev);
void delete_sysfs_file(struct device *dev);

#endif // VMEM_COMMON_H
