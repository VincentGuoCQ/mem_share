#ifndef	MEMPOOL_COMMON_H
#define MEMPOOL_COMMON_H
//#define DEBUG

#ifdef DEBUG
#define KER_DEBUG(STR, args...)	printk(STR, ##args)
#else
#define KER_DEBUG(STR, args...)
#endif

#define KER_PRT(STR, args...)	printk(STR, ##args)

static int mempool_major = 0;
static int mempool_minor= 0;

module_param(mempool_major, int, 0);
module_param(mempool_minor, int, 0);

#define LISTEN_SCHEDULE_TIME 1

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
	struct sockaddr_in host_addr;
	struct sockaddr_in host_data_addr;
	unsigned int block_inuse; 
	unsigned int state;
	struct socket *sock;
	struct socket *datasock;
	struct task_struct *CliHandleThread;

	struct mutex ptr_mutex;

};

#define MEMPOOL_STATE_LISTEN 1
#define MEMPOOL_STATE_CLOSED 2

struct mempool_dev {
	struct cdev gd;
	struct class *mempool_class;
	struct device *dev;
	dev_t devno;

	struct list_head lshd_rent_client;
	struct mutex lshd_rent_client_mutex;

	unsigned int nblk_avail;
	struct mempool_blk blk[MAX_BLK_NUM_IN_MEMPOOL];
	struct mutex blk_mutex;

	struct kmem_cache * slab_client_host;

	struct socket * listen_sock;
	struct socket * data_listen_sock;
	struct task_struct *ListenThread;

};

int mempool_listen_thread(void *data);
int create_sysfs_file(struct device *dev);
void delete_sysfs_file(struct device *dev);

#endif // MEMPOOL_COMMON_H
