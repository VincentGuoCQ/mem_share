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

char *ifname = "wlan0";
module_param(ifname, charp, 0644);
MODULE_PARM_DESC(ifname, "Send packets from which net device");

char *buffer = "Tony test from kernel!\n";
module_param(buffer, charp, 0644);
MODULE_PARM_DESC(buffer, "Packet content");

__u32 dstip = 0xc0a8016b;
module_param(dstip, uint, 0644);

__s16 dstport = 8000;
module_param(dstport, short, 0644);

long timeout = 1;
module_param(timeout, long, 0644);
MODULE_PARM_DESC(timeout, "Interval between send packets, default 1(unit second)");


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
    sin.sin_port = 0;
    err = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (err < 0) {
        printk(KERN_ALERT "sock bind err, err=%d\n", err);
        return err;
    }
    return 0;
}

static int connect_to_addr(struct socket *sock)
{
    int err;
    daddr.sin_family = AF_INET;
    daddr.sin_addr.s_addr = cpu_to_be32(dstip);
    daddr.sin_port = cpu_to_be16(dstport);
    err = sock->ops->connect(sock, (struct sockaddr*)&daddr,
            sizeof(struct sockaddr), 0);
    if (err < 0) {
        printk(KERN_ALERT "sock connect err, err=%d\n", err);
        return err;
    }
    return 0;
}

struct threadinfo{
    struct socket *sock;
    char *buffer;
};

static int sendthread(void *data)
{
    struct kvec iov;
    struct threadinfo *tinfo = data;
    struct msghdr msg;
    int len;
	msg.msg_name = (void *)&daddr;
	msg.msg_namelen = sizeof(daddr);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0; 
    while (!kthread_should_stop()) {
        iov.iov_base = (void *)tinfo->buffer;
        iov.iov_len = strlen(tinfo->buffer);
        len = kernel_sendmsg(tinfo->sock, &msg, &iov, 1, strlen(tinfo->buffer));
        if (len != strlen(buffer)) {
            printk(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%d\n",
                    len, (int)strlen(buffer));
            if (len == -ECONNREFUSED) {
                printk(KERN_ALERT "Receive Port Unreachable packet!\n");
            }
            //break;
        }
        printk(KERN_ALERT "kernel_sendmsg: len=%d\n", len);
        schedule_timeout_interruptible(timeout * HZ);
    }
    kthreadtask = NULL;
    sk_release_kernel(tinfo->sock->sk);
    kfree(tinfo);

    return 0;
}

static int __init udp_send_init(void)
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
    err = connect_to_addr(sock);
    if (err < 0) {
        printk(KERN_ALERT "sock connect err, err=%d\n", err);
        goto connect_error;
    }
    
    tinfo = kmalloc(sizeof(struct threadinfo), GFP_KERNEL);
    if (!tinfo) {
        printk(KERN_ALERT "kmalloc threadinfo err\n");
        goto kmalloc_error;
    }
    tinfo->sock = sock;
    tinfo->buffer = buffer;
    kthreadtask = kthread_run(sendthread, tinfo, "Tony-sendmsg");

    if (IS_ERR(kthreadtask)) {
        printk(KERN_ALERT "create sendmsg thread err, err=%ld\n",
                PTR_ERR(kthreadtask));
        goto thread_error;
    }
    return 0;

thread_error:
    kfree(tinfo);
kmalloc_error:
bind_error:
connect_error:
    sk_release_kernel(sock->sk);
    kthreadtask = NULL;
create_error:
    return -1;
}

static void __exit udp_send_exit(void)
{
    
    if (kthreadtask) {
        kthread_stop(kthreadtask);
    }
    printk(KERN_ALERT "UDP send quit\n");

    return;
}


module_init(udp_send_init);
module_exit(udp_send_exit); 
