#include "../include.h"
#include "../common.h"
#include "mempool_common.h"
#include "../kererr.h"
#include "../net_msg.h"

extern struct mempool_dev *Devices;
static int bind_to_device(struct socket *sock, char *ifname) {
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
    sin.sin_port = cpu_to_be16(SERHOST_LISTEN_PORT);
    ret = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (ret < 0) {
        printk(KERN_ALERT "sock bind err, err=%d\n", ret);
        return ret;
    }
    return 0;
}

static int CliRecvThread(void *data) {
    struct kvec iov;
    struct client_host *clihost = (struct client_host *)data;
    struct msghdr msg;
	struct netmsg_req *msg_req = NULL;
	struct netmsg_data *msg_wrdata = NULL;
    int len = 0;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	msg_req = (struct netmsg_req *)kmem_cache_alloc(clihost->slab_netmsg_req, GFP_USER);
	memset(msg_req, 0, sizeof(struct netmsg_req));

    while (!kthread_should_stop()) {
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
		mutex_lock(&clihost->ptr_mutex);
		if(CLIHOST_STATE_CLOSED == clihost->state) {
			mutex_unlock(&clihost->ptr_mutex);
			continue;
		}
		mutex_unlock(&clihost->ptr_mutex);
        iov.iov_base = (void *)msg_req;
        iov.iov_len = sizeof(struct netmsg_req);

		len = kernel_recvmsg(clihost->sock, &msg, &iov, 1, 
					sizeof(struct netmsg_req), MSG_DONTWAIT);
        //close of client
		if(len == 0) {
			break;
		}
		if (len < 0 || len != sizeof(struct netmsg_req)) {
            //printk(KERN_ALERT"mempool handlethread: kernel_recvmsg err, len=%d, buffer=%ld\n",
            //        len, sizeof(struct netmsg_req));
            if (len == -ECONNREFUSED) {
                printk(KERN_ALERT"mempool thread: Receive Port Unreachable packet!\n");
            }
			continue;
        }
		//request is write
		if(msg_req->msgID == NETMSG_CLI_REQUEST_WRITE) {
				msg_wrdata = (struct netmsg_data *)kmem_cache_alloc(clihost->slab_netmsg_data, GFP_USER);
				iov.iov_base = (void *)msg_wrdata;
				iov.iov_len = sizeof(struct netmsg_data);

				len = kernel_recvmsg(clihost->sock, &msg, &iov, 1,
							sizeof(struct netmsg_data), MSG_DONTWAIT);
				//close of client
				if(len == 0) {
					break;
				}
				if (len < 0 || len != sizeof(struct netmsg_data)) {
					//printk(KERN_ALERT"mempool handlethread: kernel_recvmsg err, len=%d, buffer=%ld\n",
					//        len, sizeof(struct netmsg_req));
			       if (len == -ECONNREFUSED) {
					   printk(KERN_ALERT"mempool thread: Receive Port Unreachable packet!\n");
				   }
				}
				mutex_lock(&clihost->lshd_wrdata_mutex);
				list_add_tail(&msg_wrdata->ls_req, &clihost->lshd_wrdata);
				printk(KERN_ALERT"mempool thread: add write data to list!\n");
				mutex_unlock(&clihost->lshd_wrdata_mutex);
		}
		mutex_lock(&clihost->lshd_req_msg_mutex);
		list_add_tail(&msg_req->ls_reqmsg, &clihost->lshd_req_msg);
        //printk(KERN_ALERT"mempool thread: add netmsg to list!\n");
		mutex_unlock(&clihost->lshd_req_msg_mutex);
		msg_req = (struct netmsg_req *)kmem_cache_alloc(clihost->slab_netmsg_req, GFP_USER);

    }

	kmem_cache_free(clihost->slab_netmsg_req, msg_req);

	mutex_lock(&clihost->ptr_mutex);
	if(CLIHOST_STATE_CONNECTED == clihost->state) {
		clihost->state = CLIHOST_STATE_CLOSED;
		sock_release(clihost->sock);
		//clihost->sock = NULL;
	}
	mutex_unlock(&clihost->ptr_mutex);
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
    return 0;
}

static int CliSendThread(void *data) {
    struct kvec iov;
    struct client_host *clihost = (struct client_host *)data;
    struct msghdr msg;
	struct list_head * ls_req = NULL, *next = NULL;
	struct netmsg_req *msg_req = NULL;
	struct netmsg_rpy *msg_rpy = (struct netmsg_rpy *)kmalloc(sizeof(struct netmsg_rpy), GFP_USER);
	struct netmsg_data *msg_rddata = (struct netmsg_data *)kmem_cache_alloc(clihost->slab_netmsg_data, GFP_USER);
    int len = 0;
	if(!Devices) {
		goto err_device_ptr;
	}
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

    while (!kthread_should_stop()) {
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
		mutex_lock(&clihost->ptr_mutex);
		if(CLIHOST_STATE_CLOSED == clihost->state) {
			mutex_unlock(&clihost->ptr_mutex);
			continue;
		}
		mutex_unlock(&clihost->ptr_mutex);
		mutex_lock(&clihost->lshd_req_msg_mutex);
		if(list_empty(&clihost->lshd_req_msg)) {
			mutex_unlock(&clihost->lshd_req_msg_mutex);
			continue;
		}
		list_for_each_safe(ls_req, next, &clihost->lshd_req_msg) {
			msg_req = list_entry(ls_req, struct netmsg_req, ls_reqmsg);
			list_del(&msg_req->ls_reqmsg);
			//printk(KERN_INFO"mempool CliRecvThread: req msg  delete from list\n");
			break;
		}
		mutex_unlock(&clihost->lshd_req_msg_mutex);

		memset(msg_rpy, 0, sizeof(struct netmsg_rpy));
		memset(msg_rddata, 0, sizeof(struct netmsg_data));
		
		switch(msg_req->msgID) {
			//alloc block
			case NETMSG_CLI_REQUEST_ALLOC_BLK: {
				unsigned int nIndex = 0, count = 0;

				msg_rpy->msgID = NETMSG_SER_REPLY_ALLOC_BLK;

				mutex_lock(&Devices->blk_mutex);
				for(nIndex = 0, count = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL && count < BLK_MAX_PER_REQ &&
							count < msg_req->info.req_alloc_blk.blknum; nIndex++) {
					if(Devices->blk[nIndex].avail && !Devices->blk[nIndex].inuse) {
						msg_rpy->info.rpyblk.blkinfo[count].remoteIndex = nIndex;
						msg_rpy->info.rpyblk.blkinfo[count].remoteaddr = (unsigned long)Devices->blk[nIndex].blk_addr;
						Devices->blk[nIndex].inuse = TRUE;
						count++;
					}
				}
				msg_rpy->info.rpyblk.blk_alloc = count;
				msg_rpy->info.rpyblk.blk_rest_available = 0;
				mutex_unlock(&Devices->blk_mutex);

				//printk(KERN_INFO"mempool thread: send alloc blk reply\n");
		
				break;
			}
			//write data
			case NETMSG_CLI_REQUEST_WRITE: {
				struct list_head * pd = NULL, *dnext = NULL;
				struct netmsg_data *msg_wrdata = NULL;
				unsigned int nBlkIndex = 0, nPageIndex = 0;
				mutex_lock(&clihost->lshd_wrdata_mutex);
				if(list_empty(&clihost->lshd_wrdata)) {
					mutex_unlock(&clihost->lshd_wrdata_mutex);
					break;
				}
				list_for_each_safe(pd, dnext, &clihost->lshd_wrdata) {
					msg_wrdata = list_entry(pd, struct netmsg_data, ls_req);
					list_del(&msg_wrdata->ls_req);
					//printk(KERN_INFO"mempool CliSendThread: write data delete from list\n");
					break;
				}
				mutex_unlock(&clihost->lshd_wrdata_mutex);

				nBlkIndex = msg_req->info.req_write.remoteIndex;
				nPageIndex = msg_req->info.req_write.pageIndex;

				//printk(KERN_INFO"mempool CliSendThread: nBlkIndex %d, nPageIndex %d\n", nBlkIndex, nPageIndex);
				//printk(KERN_INFO"mempool CliSendThread: data %s\n", msg_wrdata->data);
				mutex_lock(&Devices->blk_mutex);
				memcpy(Devices->blk[nBlkIndex].blk_addr + nPageIndex * VPAGE_SIZE,
							msg_wrdata->data, VPAGE_SIZE);
				mutex_unlock(&Devices->blk_mutex);
				kmem_cache_free(clihost->slab_netmsg_data, msg_wrdata);

				msg_rpy->msgID = NETMSG_SER_REPLY_WRITE;
				break;
			}
			//read data
			case NETMSG_CLI_REQUEST_READ: {
				unsigned int nBlkIndex = 0, nPageIndex = 0;

				msg_rpy->msgID = NETMSG_SER_REPLY_READ;
				msg_rpy->info.rpy_read.vpageaddr = msg_req->info.req_read.vpageaddr;
				msg_rpy->info.rpy_read.remoteIndex = msg_req->info.req_read.remoteIndex;
				msg_rpy->info.rpy_read.pageIndex = msg_req->info.req_read.pageIndex;

				nBlkIndex = msg_req->info.req_write.remoteIndex;
				nPageIndex = msg_req->info.req_write.pageIndex;

				memcpy(msg_rddata->data, Devices->blk[nBlkIndex].blk_addr + nPageIndex * VPAGE_SIZE,
							VPAGE_SIZE);
				break;
			}
			default:
				continue;
		}

		iov.iov_base = (void *)msg_rpy;
		iov.iov_len = sizeof(struct netmsg_rpy);
		len = kernel_sendmsg(clihost->sock, &msg, &iov, 1, sizeof(struct netmsg_rpy));

		if(len != sizeof(struct netmsg_rpy)) {
			//printk(KERN_INFO"kernel_sendmsg err, len=%d, buffer=%ld\n",
			//			len, sizeof(struct netmsg_rpy));
			if(len == -ECONNREFUSED) {
				printk(KERN_INFO"Receive Port Unreachable packet!\n");
			}
			//continue;
		}

		if(NETMSG_CLI_REQUEST_READ == msg_req->msgID) {
			iov.iov_base = (void *)msg_rddata;
			iov.iov_len = sizeof(struct netmsg_data);

			len = kernel_sendmsg(clihost->sock, &msg, &iov, 1, sizeof(struct netmsg_data));
			if (len < 0 || len != sizeof(struct netmsg_data)) {
				//printk(KERN_ALERT"mempool handlethread: kernel_recvmsg err, len=%d, buffer=%ld\n",
				//        len, sizeof(struct netmsg_req));
			    if (len == -ECONNREFUSED) {
					printk(KERN_ALERT"mempool thread: Receive Port Unreachable packet!\n");
				}
			}
		}
		kmem_cache_free(clihost->slab_netmsg_req, msg_req);
		//printk(KERN_INFO"mempool CliRecvThread: free from slab\n");
	}
err_device_ptr:
	kfree(msg_rpy);
	kmem_cache_free(clihost->slab_netmsg_data, msg_rddata);
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
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
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
		if(!dev->listen_sock) {
			continue;
		}
		clihost = NULL;
		ret = kernel_accept(dev->listen_sock, &cli_sock, O_NONBLOCK);
		if (ret < 0) {
		//	printk(KERN_ALERT "mempool thread: sock accept err, err=%d\n", ret);
			continue;
		}
		//create client host structure
		clihost = (struct client_host *)kmem_cache_alloc(dev->slab_client_host, GFP_USER);
		memset(clihost, 0, sizeof(struct client_host));
		if(!clihost) {
			printk(KERN_ALERT "mempool thread: create cli host err");
			continue;
		}
		clihost->sock = cli_sock;
		clihost->state = CLIHOST_STATE_CONNECTED;
		kernel_getpeername(cli_sock, (struct sockaddr *)&clihost->host_addr, &sockaddrlen);

		//init client host, slab, list_head
		mutex_init(&clihost->lshd_req_msg_mutex);
		mutex_init(&clihost->lshd_wrdata_mutex);
		mutex_init(&clihost->ptr_mutex);
		INIT_LIST_HEAD(&clihost->lshd_req_msg);
		INIT_LIST_HEAD(&clihost->lshd_wrdata);
		clihost->slab_netmsg_req = dev->slab_netmsg_req;
		clihost->slab_netmsg_data = dev->slab_netmsg_data;

		//add to list
		mutex_lock(&dev->lshd_rent_client_mutex);
		list_add_tail(&clihost->ls_rent, &dev->lshd_rent_client);
		mutex_unlock(&dev->lshd_rent_client_mutex);
		//create recive thread for client
		clihost->CliRecvThread = kthread_run(CliRecvThread, clihost, "Client Recive thread");
		if (IS_ERR(clihost->CliRecvThread)) {
			printk(KERN_ALERT "create recvmsg thread err, err=%ld\n",
                PTR_ERR(clihost->CliRecvThread));
			continue;
		}
		//create send thread for client
		clihost->CliSendThread = kthread_run(CliSendThread, clihost, "Client Send thread");
		if (IS_ERR(clihost->CliSendThread)) {
			printk(KERN_ALERT "create recvmsg thread err, err=%ld\n",
			PTR_ERR(clihost->CliSendThread));
			continue;
		}
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
    }
	while(!kthread_should_stop()) {
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
    return 0;

listen_error:
bind_error:
	if(dev->listen_sock) {
		sock_release(dev->listen_sock);
		//dev->listen_sock = NULL;
	}
	while(!kthread_should_stop()) {
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
create_error:
null_ptr_error:
    return -1;
}
