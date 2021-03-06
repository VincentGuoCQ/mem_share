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
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/unaligned.h>
#include <linux/kthread.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tony ");

char *ifname = "eth0";
module_param(ifname, charp, 0644);
MODULE_PARM_DESC(ifname, "Send packets from which net device");


long timeout = 1;
module_param(timeout, long, 0644);
MODULE_PARM_DESC(timeout, "Interval between recv packets, default 1(unit second)");


static struct task_struct *kthreadtask = NULL;
struct sockaddr_in daddr;

static int bind_to_device(struct socket *sock, char *ifname)
{
    struct net *net;
    struct net_device *dev;
    __be32 addr;
    struct sockaddr_in sin;
    int err;
    net = sock_net(sock->sk);
    dev = __dev_get_by_name(net, ifname);

    if (!dev) {
        printk(KERN_ALERT "No such device named %s\n", ifname);
        return -ENODEV;    
    }
    addr = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sin.sin_port = cpu_to_be16(8000);
    err = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (err < 0) {
        printk(KERN_ALERT "sock bind err, err=%d\n", err);
        return err;
    }
    return 0;
}

struct threadinfo{
    struct socket *sock;
	char buffer[100];
};

static int recvthread(void *data)
{
    struct kvec iov;
    struct threadinfo *tinfo = data;
    struct msghdr msg;
    int len;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
    while (!kthread_should_stop()) {
        iov.iov_base = (void *)tinfo->buffer;
        iov.iov_len = 100;
        len = kernel_recvmsg(tinfo->sock, &msg, &iov, 1, 100, MSG_DONTWAIT);
        if (len < 0) {
            printk(KERN_ALERT "kernel_recvmsg err, len=%d, buffer=%ld\n",
                    len, sizeof(tinfo->buffer));
            if (len == -ECONNREFUSED) {
                printk(KERN_ALERT "Receive Port Unreachable packet!\n");
            }
            //break;
        }
		else {
			printk(KERN_ALERT"%s\n", tinfo->buffer);
		}
        schedule_timeout_interruptible(timeout * HZ);
    }
    kthreadtask = NULL;
    sk_release_kernel(tinfo->sock->sk);
    kfree(tinfo);

    return 0;
}

static int __init udp_recv_init(void)
{
    int err = 0;
    struct socket *sock;
    struct threadinfo *tinfo;

    err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (err < 0) {
        printk(KERN_ALERT "UDP create sock err, err=%d\n", err);
        goto create_error;
    }
    sock->sk->sk_reuse = 1;


    err = bind_to_device(sock, ifname);
    if (err < 0) {
        printk(KERN_ALERT "Bind to %s err, err=%d\n", ifname, err);
        goto bind_error;
    }    
    err = kernel_listen(sock, 5);
    if (err < 0) {
        printk(KERN_ALERT "sock listen err, err=%d\n", err);
        goto listen_error;
    }
    
    tinfo = kmalloc(sizeof(struct threadinfo), GFP_KERNEL);
    if (!tinfo) {
        printk(KERN_ALERT "kmalloc threadinfo err\n");
        goto kmalloc_error;
    }
    err = kernel_accept(sock, &tinfo->sock, 0);
    if (err < 0) {
        printk(KERN_ALERT "sock accept err, err=%d\n", err);
        goto accept_error;
	}

    kthreadtask = kthread_run(recvthread, tinfo, "Tony-recvmsg");

    if (IS_ERR(kthreadtask)) {
        printk(KERN_ALERT "create recvmsg thread err, err=%ld\n",
                PTR_ERR(kthreadtask));
        goto thread_error;
    }
    return 0;

thread_error:
    kfree(tinfo);
accept_error:
kmalloc_error:
listen_error:
bind_error:
    sk_release_kernel(sock->sk);
    kthreadtask = NULL;
create_error:
    return -1;
}

static void __exit udp_recv_exit(void)
{
    
    if (kthreadtask) {
        kthread_stop(kthreadtask);
    }
    printk(KERN_ALERT "UDP recv quit\n");

    return;
}


module_init(udp_recv_init);
module_exit(udp_recv_exit); 
