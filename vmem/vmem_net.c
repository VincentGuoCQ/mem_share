#define VMEM

#include "../common.h"
#include <linux/kthread.h>
#include "../kererr.h"
#include "../net_msg.h"

extern struct vmem_dev *Devices;

static int bind_to_device(struct socket *sock, char *ifname, struct server_host *serhost)
{
    struct net *net;
    struct net_device *dev;
    __be32 addr;
	struct sockaddr_in sin;
	int ret = KERERR_SUCCESS;

    net = sock_net(sock->sk);
    dev = __dev_get_by_name(net, ifname);

    if (!dev) {
        printk(KERN_ALERT "No such device named %s\n", ifname);
        return -ENODEV;    
    }
    addr = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sin.sin_port = 0;
    ret = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (ret < 0) {
        printk(KERN_ALERT "sock bind err, err=%d\n", ret);
        return ret;
    }
    return 0;
}

static int connect_to_addr(struct socket *sock, struct server_host *serhost)
{
    int ret = KERERR_SUCCESS;
    serhost->host_addr.sin_family = AF_INET;
    //serhost->host_addr.sin_addr.s_addr = cpu_to_be32(dstip);
    serhost->host_addr.sin_port = cpu_to_be16(SERHOST_LISTEN_PORT);
    ret = sock->ops->connect(sock, (struct sockaddr*)&serhost->host_addr,
            sizeof(struct sockaddr), 0);
    if (ret < 0) {
        printk(KERN_ALERT "sock connect err, err=%d\n", ret);
        return ret;
    }
    return ret;
}

static int HandleThread(void *data) {
    struct kvec iov;
    struct server_host *serhost = (struct server_host *)data;
	struct msghdr msg;
	struct netmsg_req msg_req;
	struct netmsg_rpy msg_rpy;
    int len;

	memset(&msg_req, 0 ,sizeof(struct netmsg_req));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

    while (!kthread_should_stop()) {
        iov.iov_base = (void *)&msg_req;
        iov.iov_len = sizeof(struct netmsg_req);
        len = kernel_sendmsg(serhost->sock, &msg, &iov, 1, sizeof(struct netmsg_req));
        if (len != sizeof(struct netmsg_req)) {
            printk(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%ld\n",
                    len, sizeof(struct netmsg_req));
            if (len == -ECONNREFUSED) {
                printk(KERN_ALERT "Receive Port Unreachable packet!\n");
            }
            //break;
        }
        printk(KERN_ALERT "kernel_sendmsg: len=%d\n", len);
        schedule_timeout_interruptible(1 * HZ);
    }
//	serhost->HandleThread = NULL;
//	if(serhost->sock) {
//		sock_release(serhost->sock);
//		serhost->sock = NULL;
//	}

    return 0;
}

int vmem_net_init(struct server_host *serhost) {
    int ret = KERERR_SUCCESS;

    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(serhost->sock));
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "UDP create sock err, err=%d\n", ret);
        goto create_error;
    }
    serhost->sock->sk->sk_reuse = 1;

    ret = bind_to_device(serhost->sock, VMEM_IF_NAME, serhost);
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "Bind to %s err, err=%d\n", VMEM_IF_NAME, ret);
        goto bind_error;
    }    
    ret = connect_to_addr(serhost->sock, serhost);
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "sock connect err, err=%d\n", ret);
        goto connect_error;
    }
	serhost->host_addr.sin_family = AF_INET;
	serhost->host_addr.sin_port = cpu_to_be16(SERHOST_LISTEN_PORT);
	ret = kernel_connect(serhost->sock, (struct sockaddr *)&serhost->host_addr, sizeof(struct sockaddr), 0);
	if(ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "sock connect server err, err=%d\n", ret);
        //goto connect_error;
	}
	serhost->HandleThread = kthread_run(HandleThread, (void *)serhost, "HandleThread");
    if (IS_ERR(serhost->HandleThread)) {
        printk(KERN_ALERT "create sendmsg thread err, err=%ld\n",
                PTR_ERR(serhost->HandleThread));
        goto thread_error;
    }
    return ret;

thread_error:
connect_error:
bind_error:
//	if(serhost->sock) {
//		sock_release(serhost->sock);
//		serhost->sock = NULL;
//	}
create_error:
    return ret;
}

int vmem_daemon(void *data) {
	struct vmem_dev * pdev = (struct vmem_dev *)data;
	unsigned sumpage = 0, sumblk = 0, nIndex = 0;
	while(!kthread_should_stop()) {
        schedule_timeout_interruptible(CALCULATE_PERIOD * HZ);
		for(nIndex = 0, sumpage = 0, sumblk = 0; nIndex < BLK_NUM_MAX; nIndex++) {
			if(pdev->addr_entry[nIndex].mapped) {
				sumblk++;
				sumpage += pdev->addr_entry[nIndex].inuse_count;
			}
		}
		printk(KERN_INFO"sumpage=%d, sumblk=%d\n", sumpage, sumblk);
		//memory over upper limit
		if(sumpage >= (unsigned int)(3 * ((sumblk * VPAGE_NUM_IN_BLK) >> 2))) {
			struct list_head *p = NULL;
			struct server_host *serhost = NULL; 
			printk(KERN_INFO"over upper limit\n");
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each(p, &Devices->lshd_available) {
				serhost = list_entry(p, struct server_host, ls_available);
				list_del(p);
				break;
			}
			mutex_unlock(&Devices->lshd_avail_mutex);
			if(NULL == serhost) {
				continue;
			}

			vmem_net_init(serhost);

			mutex_lock(&Devices->lshd_inuse_mutex);
			list_add_tail(&serhost->ls_inuse, &Devices->lshd_inuse);
			mutex_unlock(&Devices->lshd_inuse_mutex);
			continue;
		}
		//memory below lower limit
		if(sumpage <= (unsigned int)(((sumblk * VPAGE_NUM_IN_BLK) >> 2))) {
			printk(KERN_INFO"over lower limit");
			continue;
		}
	}
	return 0;
}
