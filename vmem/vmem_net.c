#define VMEM

#include "../common.h"
#include <linux/kthread.h>
#include "../kererr.h"
static int bind_to_device(struct socket *sock, char *ifname, struct server_host *serhost)
{
    struct net *net;
    struct net_device *dev;
    __be32 addr;
	struct sockaddr_in sin;
	int ret = KERNEL_SUCCESS;

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
    ret = sock->ops->connect(sock, (struct sockaddr*)&daddr,
            sizeof(struct sockaddr), 0);
    if (ret < 0) {
        printk(KERN_ALERT "sock connect err, err=%d\n", ret);
        return ret;
    }
    return ret;
}

static int HandleThread(void *data) {
//    struct kvec iov;
//    struct threadinfo *tinfo = data;
//    struct msghdr msg;
//    int len;
//	msg.msg_name = (void *)&daddr;
//	msg.msg_namelen = sizeof(daddr);
//	msg.msg_control = NULL;
//	msg.msg_controllen = 0;
//	msg.msg_flags = 0; 
//    while (!kthread_should_stop()) {
//        iov.iov_base = (void *)tinfo->buffer;
//        iov.iov_len = strlen(tinfo->buffer);
//        len = kernel_sendmsg(tinfo->sock, &msg, &iov, 1, strlen(tinfo->buffer));
//        if (len != strlen(buffer)) {
//            printk(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%d\n",
//                    len, (int)strlen(buffer));
//            if (len == -ECONNREFUSED) {
//                printk(KERN_ALERT "Receive Port Unreachable packet!\n");
//            }
//            //break;
//        }
//        printk(KERN_ALERT "kernel_sendmsg: len=%d\n", len);
//        schedule_timeout_interruptible(timeout * HZ);
//    }
//    kthreadtask = NULL;
//    sk_release_kernel(tinfo->sock->sk);
//    kfree(tinfo);
//
//    return 0;
}

int vmem_net_init(struct vmem_blk *blk, struct server_host *serhost) {
    int ret = KERERR_SUCCESS;

    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(serhost->sock));
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "UDP create sock err, err=%d\n", ret);
        goto create_error;
    }
    serhost->sock->sk->sk_reuse = 1;

    ret = bind_to_device(serhost->sock, ifname, serhost);
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "Bind to %s err, err=%d\n", ifname, ret);
        goto bind_error;
    }    
    ret = connect_to_addr(serhost->sock);
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "sock connect err, err=%d\n", ret);
        goto connect_error;
    }

    serhost->HandleThread = kthread_run(HandleThread, (void *)serhost, "Tony-sendmsg");

    if (IS_ERR(serhost->HandleThread)) {
        printk(KERN_ALERT "create sendmsg thread err, err=%ld\n",
                PTR_ERR(serhost->HandleThread));
        goto thread_error;
    }
    return ret;

thread_error:
bind_error:
connect_error:
    sock_release(serhost->sock);
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
		printk(KERN_INFO"sumpage=%d, sumblk=%d", sumpage, sumblk);
		//memory over upper limit
		if(sumpage >= (unsigned int)(UPPER_LIMIT_PRECENT * (sumblk * VPAGE_NUM_IN_BLK))) {
			continue;
		}
		//memory below lower limit
		if(sumpage <= (unsigned int)(LOWER_LIMIT_PRECENT * (sumblk * VPAGE_NUM_IN_BLK))) {
			continue;
		}
	}
	return 0;
}
