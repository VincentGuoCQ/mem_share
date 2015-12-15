#include "../include.h"
#include "../common.h"
#include "mempool_common.h"
#include "../kererr.h"
#include "../net_msg.h"

extern struct mempool_dev *Devices;
static int bind_to_device(struct socket *sock, char *ifname, unsigned short port) {
    struct net *net;
    struct net_device *dev;
    __be32 addr;
    struct sockaddr_in sin;
    int ret;
    net = sock_net(sock->sk);
    dev = __dev_get_by_name(net, ifname);

    if (!dev) {
        KER_DEBUG(KERN_ALERT "No such device named %s\n", ifname);
        return -ENODEV;    
    }
    addr = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sin.sin_port = cpu_to_be16(port);
    ret = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "sock bind err, err=%d\n", ret);
        return ret;
    }
    return 0;
}

static int CliRecvThread(void *data) {
    struct kvec recviov, recvdataiov, sendiov, senddataiov;
    struct client_host *clihost = (struct client_host *)data;
    struct msghdr recvmsg, sendmsg, senddatamsg, recvdatamsg;
	struct netmsg_req msg_req;
	struct netmsg_data *msg_wrdata = (struct netmsg_data *)kmalloc(sizeof(struct netmsg_data), GFP_USER);
	struct netmsg_rpy msg_rpy;
	struct netmsg_data *msg_rddata = (struct netmsg_data *)kmalloc(sizeof(struct netmsg_data), GFP_USER);
    int len = 0;

	memset(&recvmsg, 0, sizeof(struct msghdr));
	memset(&recvdatamsg, 0, sizeof(struct msghdr));
	memset(&sendmsg, 0, sizeof(struct msghdr));
	memset(&senddatamsg, 0, sizeof(struct msghdr));

	sendmsg.msg_name = (void *)&clihost->host_addr;
	sendmsg.msg_namelen = sizeof(struct sockaddr_in);
	senddatamsg.msg_name = (void *)&clihost->host_data_addr;
	senddatamsg.msg_namelen = sizeof(struct sockaddr_in);

	memset(&recviov, 0, sizeof(struct kvec));
	memset(&recvdataiov, 0, sizeof(struct kvec));
	memset(&sendiov, 0, sizeof(struct kvec));
	memset(&senddataiov, 0, sizeof(struct kvec));
    recviov.iov_base = (void *)&msg_req.info;
    recviov.iov_len = sizeof(struct req_info);
	sendiov.iov_base = (void *)&msg_rpy.info;
	sendiov.iov_len = sizeof(struct rpy_info);
	recvdataiov.iov_base = (void *)&msg_wrdata->info;
	recvdataiov.iov_len = sizeof(struct data_info);
	senddataiov.iov_base = (void *)&msg_rddata->info;
	senddataiov.iov_len = sizeof(struct data_info);

    while (!kthread_should_stop()) {
        //schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
		memset(&msg_req, 0, sizeof(struct netmsg_req));
		memset(&msg_rpy, 0, sizeof(struct netmsg_rpy));

		mutex_lock(&clihost->ptr_mutex);
		if(CLIHOST_STATE_CLOSED == clihost->state) {
			mutex_unlock(&clihost->ptr_mutex);
			continue;
		}
		mutex_unlock(&clihost->ptr_mutex);

		len = kernel_recvmsg(clihost->sock, &recvmsg, &recviov, 1, 
					sizeof(struct req_info), 0);
        KER_DEBUG(KERN_ALERT"mempool handlethread: kernel_recvmsg en=%d\n",len);
        //close of client
		if(len == 0) {
			break;
		}
		if (len < 0 || len != sizeof(struct req_info)) {
            KER_DEBUG(KERN_ALERT"mempool handlethread: kernel_recvmsg err, len=%d, buffer=%ld\n",
                    len, sizeof(struct req_info));
            if (len == -ECONNREFUSED) {
                KER_DEBUG(KERN_ALERT"mempool thread: Receive Port Unreachable packet!\n");
            }
			continue;
        }
		switch(msg_req.info.msgID) {
			//alloc block
			case NETMSG_CLI_REQUEST_ALLOC_BLK: {
				unsigned int nIndex = 0, count = 0;

				KER_PRT(KERN_INFO"begin to alloc\n");
				msg_rpy.info.msgID = NETMSG_SER_REPLY_ALLOC_BLK;

				mutex_lock(&Devices->blk_mutex);
				for(nIndex = 0, count = 0; nIndex < MAX_BLK_NUM_IN_MEMPOOL && count < BLK_MAX_PER_REQ &&
							count < msg_req.info.data.req_alloc_blk.blknum; nIndex++) {
					if(Devices->blk[nIndex].avail && !Devices->blk[nIndex].inuse) {
						msg_rpy.info.data.rpyblk.blkinfo[count].remoteIndex = nIndex;
						Devices->blk[nIndex].inuse = TRUE;
						count++;
					}
				}
				mutex_unlock(&Devices->blk_mutex);

				Devices->nblk_avail -= count; 
				clihost->block_inuse += count;
				msg_rpy.info.data.rpyblk.blk_alloc = count;
				msg_rpy.info.data.rpyblk.blk_rest_available = Devices->nblk_avail;

				KER_DEBUG(KERN_INFO"mempool thread: send alloc blk reply\n");
		
				break;
			}
			//write data
			case NETMSG_CLI_REQUEST_WRITE: {
				unsigned int nBlkIndex = 0, nPageIndex = 0;

				len = kernel_recvmsg(clihost->datasock, &recvmsg, &recvdataiov, 1, sizeof(struct data_info), 0);
				if (len < 0 || len != sizeof(struct data_info)) {
					KER_DEBUG(KERN_ALERT"mempool handlethread: kernel_recvmsg err, len=%d, buffer=%ld\n",
					        len, sizeof(struct req_info));
				    if (len == -ECONNREFUSED) {
						KER_DEBUG(KERN_ALERT"mempool thread: Receive Port Unreachable packet!\n");
					}
				}

				KER_PRT(KERN_INFO"begin to write\n");

				nBlkIndex = msg_req.info.data.req_write.remoteIndex;
				nPageIndex = msg_req.info.data.req_write.pageIndex;

				KER_DEBUG(KERN_INFO"mempool CliSendThread: nBlkIndex %d, nPageIndex %d\n", nBlkIndex, nPageIndex);
				KER_DEBUG(KERN_INFO"mempool CliSendThread: data %s\n", msg_wrdata->data);
				mutex_lock(&Devices->blk_mutex);
				memcpy(Devices->blk[nBlkIndex].blk_addr + nPageIndex * VPAGE_SIZE,
							msg_wrdata->info.data, VPAGE_SIZE);
				mutex_unlock(&Devices->blk_mutex);

				msg_rpy.info.msgID = NETMSG_SER_REPLY_WRITE;

				KER_PRT(KERN_INFO"end to write\n");
				break;
			}
			//read data
			case NETMSG_CLI_REQUEST_READ: {
				unsigned int nBlkIndex = 0, nPageIndex = 0;

				KER_PRT(KERN_INFO"begin to read\n");
				msg_rpy.info.msgID = NETMSG_SER_REPLY_READ;
				msg_rpy.info.data.rpy_read.vpageaddr = msg_req.info.data.req_read.vpageaddr;
				msg_rpy.info.data.rpy_read.remoteIndex = msg_req.info.data.req_read.remoteIndex;
				msg_rpy.info.data.rpy_read.pageIndex = msg_req.info.data.req_read.pageIndex;

				nBlkIndex = msg_req.info.data.req_write.remoteIndex;
				nPageIndex = msg_req.info.data.req_write.pageIndex;

				memcpy(msg_rddata->info.data, Devices->blk[nBlkIndex].blk_addr + nPageIndex * VPAGE_SIZE,
							VPAGE_SIZE);
				KER_PRT(KERN_INFO"end to read\n");

				len = kernel_sendmsg(clihost->datasock, &senddatamsg, &senddataiov, 1, sizeof(struct data_info));

				if (len < 0 || len != sizeof(struct data_info)) {
					KER_DEBUG(KERN_ALERT"mempool handlethread: kernel_sendmsg err, len=%d, buffer=%ld\n",
					        len, sizeof(struct req_info));
				    if (len == -ECONNREFUSED) {
						KER_DEBUG(KERN_ALERT"mempool thread: Receive Port Unreachable packet!\n");
					}
				}
				break;
			}
			//heart beat
			case NETMSG_CLI_REQUEST_HEARTBEAT: {
				msg_rpy.info.msgID = NETMSG_SER_REPLY_HEARTBEAT;
				msg_rpy.info.data.rpy_heartbeat.blk_rest_available = Devices->nblk_avail;
				break;
			}
			default:
				continue;
		}

		len = kernel_sendmsg(clihost->sock, &sendmsg, &sendiov, 1, sizeof(struct rpy_info));

		if(len != sizeof(struct rpy_info)) {
			KER_DEBUG(KERN_INFO"kernel_sendmsg err, len=%d, buffer=%ld\n",
						len, sizeof(struct rpy_info));
			if(len == -ECONNREFUSED) {
				KER_DEBUG(KERN_INFO"Receive Port Unreachable packet!\n");
			}
			//continue;
		}
		KER_PRT(KERN_INFO"end\n");

    }


	mutex_lock(&clihost->ptr_mutex);
	if(CLIHOST_STATE_CONNECTED == clihost->state) {
		clihost->state = CLIHOST_STATE_CLOSED;
		sock_release(clihost->sock);
		sock_release(clihost->datasock);
		//clihost->sock = NULL;
	}
	mutex_unlock(&clihost->ptr_mutex);
	kfree(msg_wrdata);
	kfree(msg_rddata);
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
    return 0;
}

int mempool_listen_thread(void *data)
{
    int ret = KERERR_SUCCESS;
	struct mempool_dev *dev = (struct mempool_dev *)data;
	struct socket *cli_sock = NULL, *data_sock = NULL;
	struct client_host *clihost = NULL;
	int sockaddrlen = sizeof(struct sockaddr);

	if(!dev) {
		goto null_ptr_error; 
	}
	//init mempool listen socket
    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(dev->listen_sock));
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "mempool listen thread: TCP  create listen sock err, err=%d\n", ret);
        goto create_error;
    }
    dev->listen_sock->sk->sk_reuse = 1;
    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(dev->data_listen_sock));
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "mempool listen thread: TCP  create listen sock err, err=%d\n", ret);
        goto create_data_error;
    }
    dev->data_listen_sock->sk->sk_reuse = 1;

	//bind to interwork interface
    ret = bind_to_device(dev->listen_sock, MEMPOOL_IF_NAME, SERHOST_LISTEN_PORT);
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "mempool listen thread: Bind to %s err, err=%d\n", MEMPOOL_IF_NAME, ret);
        goto bind_error;
    }
    ret = bind_to_device(dev->data_listen_sock, MEMPOOL_IF_NAME, DATA_PORT);
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "mempool listen thread: Bind to %s err, err=%d\n", MEMPOOL_IF_NAME, ret);
        goto bind_data_error;
    }
	//begin listen
    ret = kernel_listen(dev->listen_sock, LISTEM_MAX_QUEUE);
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "mempool thread: sock listen err, err=%d\n", ret);
        goto listen_error;
    }
    ret = kernel_listen(dev->data_listen_sock, LISTEM_MAX_QUEUE);
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "mempool thread: sock listen err, err=%d\n", ret);
        goto listen_data_error;
    }
	//accept loop
	while(!kthread_should_stop()) {
        schedule_timeout_interruptible(LISTEN_SCHEDULE_TIME * HZ);
		if(!dev->listen_sock) {
			continue;
		}
		clihost = NULL;
		cli_sock = NULL;
		data_sock = NULL;
		ret = kernel_accept(dev->listen_sock, &cli_sock, O_NONBLOCK);
		if (ret < 0) {
			//KER_DEBUG(KERN_ALERT "mempool thread: sock accept err, err=%d\n", ret);
			continue;
		}
        schedule_timeout_interruptible(LISTEN_SCHEDULE_TIME * HZ);
		ret = kernel_accept(dev->data_listen_sock, &data_sock, O_NONBLOCK);
		if (ret < 0) {
			//KER_DEBUG(KERN_ALERT "mempool thread: sock accept err, err=%d\n", ret);
			continue;
		}
		//create client host structure
		clihost = (struct client_host *)kmem_cache_alloc(dev->slab_client_host, GFP_USER);
		memset(clihost, 0, sizeof(struct client_host));
		if(!clihost) {
			KER_DEBUG(KERN_ALERT "mempool thread: create clihost err");
			continue;
		}
		clihost->sock = cli_sock;
		clihost->datasock = data_sock;
		clihost->state = CLIHOST_STATE_CONNECTED;
		kernel_getpeername(cli_sock, (struct sockaddr *)&clihost->host_addr, &sockaddrlen);
		kernel_getpeername(data_sock, (struct sockaddr *)&clihost->host_data_addr, &sockaddrlen);

		//init client host, slab, list_head
		mutex_init(&clihost->ptr_mutex);

		//add to list
		mutex_lock(&dev->lshd_rent_client_mutex);
		list_add_tail(&clihost->ls_rent, &dev->lshd_rent_client);
		mutex_unlock(&dev->lshd_rent_client_mutex);
		//create recive thread for client
		clihost->CliHandleThread = kthread_run(CliRecvThread, clihost, "Client Recive thread");
		if (IS_ERR(clihost->CliHandleThread)) {
			KER_DEBUG(KERN_ALERT "create recvmsg thread err, err=%ld\n",
                PTR_ERR(clihost->CliHandleThread));
			continue;
		}
    }
	while(!kthread_should_stop()) {
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
    return 0;
listen_data_error:
listen_error:
bind_data_error:
bind_error:
	if(dev->data_listen_sock) {
		sock_release(dev->data_listen_sock);
	}
create_data_error:
	if(dev->listen_sock) {
		sock_release(dev->listen_sock);
	}
create_error:
null_ptr_error:
	while(!kthread_should_stop()) {
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
    return -1;
}
