#ifndef	MEMPOOL_COMMON_H
#define MEMPOOL_COMMON_H

static int mempool_major = 0;
static int mempool_minor= 0;

module_param(mempool_major, int, 0);
module_param(mempool_minor, int, 0);

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
	struct mutex lshd_wrdata_mutex;
	struct list_head lshd_wrdata;

	struct kmem_cache * slab_netmsg_req;
	struct kmem_cache * slab_netmsg_data;
};

#define MEMPOOL_STATE_LISTEN 1
#define MEMPOOL_STATE_CLOSED 2

struct mempool_dev {
	struct request_queue *queue;
	struct cdev gd;
	struct class *mempool_class;
	struct device *dev;
	dev_t devno;

	struct list_head lshd_rent_client;
	struct mutex lshd_rent_client_mutex;

	struct mempool_blk blk[MAX_BLK_NUM_IN_MEMPOOL];
	struct mutex blk_mutex;

	struct kmem_cache * slab_client_host;

	struct socket * listen_sock;
	struct task_struct *ListenThread;

	struct kmem_cache * slab_netmsg_req;
	struct kmem_cache * slab_netmsg_data;
};

int mempool_listen_thread(void *data);
int create_sysfs_file(struct device *dev);
void delete_sysfs_file(struct device *dev);

#endif // MEMPOOL_COMMON_H
