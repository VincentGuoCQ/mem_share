#define MEMPOOL

#include "../common.h"
#include "../kererr.h"
#include "../net_msg.h"

static int bind_to_device(struct socket *sock, char *ifname)
{
    struct net *net;
    struct net_device *dev;
    __be32 addr;
    struct sockaddr_in sin;
    int ret;
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
    ret = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (ret < 0) {
        printk(KERN_ALERT "sock bind err, err=%d\n", ret);
        return ret;
    }
    return 0;
}

static int handlethread(void *data)
{
    struct kvec iov;
    struct client_host *clihost = (struct client_host *)data;
    struct msghdr msg;
	struct netmsg_control msgctr;
    int len;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
    while (!kthread_should_stop()) {
		if(!clihost->sock) {
			continue;
		}
        iov.iov_base = &msgctr;
        iov.iov_len = sizeof(msgctr);
        len = kernel_recvmsg(clihost->sock, &msg, &iov, 1, 100, MSG_WAITFORONE);
        //close of client
		if(len == 0) {
			break;
		}
		if (len < 0) {
            printk(KERN_ALERT "mempool handlethread: kernel_recvmsg err, len=%d, buffer=%ld\n",
                    len, sizeof(msgctr));
            if (len == -ECONNREFUSED) {
                printk(KERN_ALERT "mempool handlethread: Receive Port Unreachable packet!\n");
            }
			continue;
        }
    }
    sock_release(clihost->sock);
	clihost->sock = NULL;
    return 0;
}

int mempool_listen_thread(void *data)
{
    int ret = KERERR_SUCCESS;
	struct mempool_dev *dev = (struct mempool_dev *)data;
	struct socket *cli_sock = NULL;
	struct client_host *clihost = NULL;
	int sockaddrlen = sizeof(struct sockaddr);

	if(!dev) {
		goto null_ptr_error; 
	}
	//init mempool listen socket
    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(dev->listen_sock));
    if (ret < 0) {
        printk(KERN_ALERT "mempool listen thread: TCP  create listen sock err, err=%d\n", ret);
        goto create_error;
    }
    dev->listen_sock->sk->sk_reuse = 1;

	//bind to interwork interface
    ret = bind_to_device(dev->listen_sock, MEMPOOL_IF_NAME);
    if (ret < 0) {
        printk(KERN_ALERT "mempool listen thread: Bind to %s err, err=%d\n", MEMPOOL_IF_NAME, ret);
        goto bind_error;
    }
	//begin listen
    ret = kernel_listen(dev->listen_sock, LISTEM_MAX_QUEUE);
    if (ret < 0) {
        printk(KERN_ALERT "mempool thread: sock listen err, err=%d\n", ret);
        goto listen_error;
    }
	//accept loop
	while(!kthread_should_stop()) {
		if(!dev->listen_sock) {
			continue;
		}
		clihost = NULL;
		ret = kernel_accept(dev->listen_sock, &cli_sock, O_NONBLOCK);
		if (ret < 0) {
			printk(KERN_ALERT "mempool thread: sock listen err, err=%d\n", ret);
			continue;
		}
		//create client host structure
		clihost = (struct client_host *)kmem_cache_alloc(dev->slab_client_host, GFP_USER);
		clihost->sock = cli_sock;
		clihost->state = CLIHOST_STATE_CONNECTED;
		kernel_getpeername(cli_sock, (struct sockaddr *)&clihost->host_addr, &sockaddrlen);

		//init client host
		mutex_init(&clihost->lshd_msgqueue_mutex);
		INIT_LIST_HEAD(&clihost->lshd_msgqueue);

		//add to list
		mutex_lock(&dev->lshd_rent_client_mutex);
		list_add_tail(&dev->lshd_rent_client, &clihost->ls_rent);
		mutex_unlock(&dev->lshd_rent_client_mutex);
		clihost->handlethread = kthread_run(handlethread, clihost, "mempool handle thread");
		if (IS_ERR(clihost->handlethread)) {
			printk(KERN_ALERT "create recvmsg thread err, err=%ld\n",
                PTR_ERR(clihost->handlethread));
			continue;
		}
        schedule_timeout_interruptible(1 * HZ);
    }

    return 0;

listen_error:
bind_error:
	if(dev->listen_sock) {
		sock_release(dev->listen_sock);
		dev->listen_sock = NULL;
	}
create_error:
null_ptr_error:
    return -1;
}
