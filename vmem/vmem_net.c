#include "../include.h"
#include "../common.h"
#include "vmem_common.h"
#include <linux/kthread.h>
#include "../kererr.h"
#include "../net_msg.h"

extern struct vmem_dev *Devices;

int bind_to_device(struct socket *sock, char *ifname) {
    struct net *net;
    struct net_device *dev;
    __be32 addr;
	struct sockaddr_in sin;
	int ret = KERERR_SUCCESS;

    net = sock_net(sock->sk);
    dev = __dev_get_by_name(net, ifname);

    if (!dev) {
        KER_DEBUG(KERN_ALERT "No such device named %s\n", ifname);
        return -ENODEV;
    }
    addr = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sin.sin_port = 0;
    ret = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "sock bind err, err=%d\n", ret);
        return ret;
    }
    return 0;
}

int connect_to_addr(struct socket *sock, struct server_host *serhost, unsigned short port) {
    int ret = KERERR_SUCCESS;
    serhost->host_addr.sin_family = AF_INET;
    serhost->host_addr.sin_port = cpu_to_be16(port);
    ret = sock->ops->connect(sock, (struct sockaddr*)&serhost->host_addr,
            sizeof(struct sockaddr), 0);
    if (ret < 0) {
        KER_DEBUG(KERN_ALERT "sock connect err, err=%d\n", ret);
        return ret;
    }
    return ret;
}

int SerRecvThread(void *data) {
    struct kvec iov;
    struct server_host *serhost = (struct server_host *)data;
	struct msghdr recvmsg, recvdatamsg;
	struct netmsg_rpy msg_rpy;
	struct netmsg_data *msg_rddata = NULL;
	int len = 0;
	if(!Devices) {
		goto err_device_ptr;
	}
	memset(&recvmsg, 0, sizeof(struct msghdr));
	memset(&recvdatamsg, 0, sizeof(struct msghdr));
	while(!kthread_should_stop()) {
		//schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
		mutex_lock(&serhost->ptr_mutex);
		if(serhost->state == CLIHOST_STATE_CLOSED || !serhost->sock) {
			mutex_unlock(&serhost->ptr_mutex);
			break;
		}
		mutex_unlock(&serhost->ptr_mutex);
		memset(&msg_rpy, 0, sizeof(struct netmsg_rpy));

		iov.iov_base = (void *)&msg_rpy.info;
		iov.iov_len = sizeof(struct rpy_info);

		len = kernel_recvmsg(serhost->sock, &recvmsg, &iov, 1,
					sizeof(struct rpy_info), MSG_WAITFORONE);
		//close of client
		if(len == 0) {
			break;
		}
		if(len < 0 || len != sizeof(struct rpy_info)) {
			if(len == -ECONNREFUSED) {
				KER_DEBUG(KERN_INFO"vmem thread: recvice err");
			}
			continue;
		}
		KER_DEBUG(KERN_INFO"vmem thread: recvice netmsg_rpy:%d", msg_rpy.info.msgID);
		switch(msg_rpy.info.msgID) {
			//alloc block
			case NETMSG_SER_REPLY_ALLOC_BLK:{
				unsigned int  nIndex = 0, count = 0;
				KER_DEBUG(KERN_INFO"vmem thread: recvice rpy: alloc blk");
				for(nIndex = 0, count = 0; nIndex < BLK_NUM_MAX &&
							count < msg_rpy.info.data.rpyblk.blk_alloc; nIndex++) {
					if(FALSE == Devices->addr_entry[nIndex].inuse) {
						Devices->addr_entry[nIndex].entry.vmem.blk_remote_index =
							msg_rpy.info.data.rpyblk.blkinfo[count].remoteIndex;
						Devices->addr_entry[nIndex].entry.vmem.blk_size = BLK_SIZE; 
						Devices->addr_entry[nIndex].entry.vmem.serhost = serhost;
						Devices->addr_entry[nIndex].entry.vmem.inuse = TRUE;
						Devices->addr_entry[nIndex].remote = TRUE;
						Devices->addr_entry[nIndex].inuse = TRUE;
						count ++;
					}
				}
				serhost->block_inuse += count;
				serhost->block_available = msg_rpy.info.data.rpyblk.blk_rest_available;
				break;
			}
			//read page
			case NETMSG_SER_REPLY_READ: {
				msg_rddata = (struct netmsg_data *)kmem_cache_alloc(serhost->slab_netmsg_data, GFP_USER);
				memset(msg_rddata, 0, sizeof(struct netmsg_data));
				iov.iov_base = (void *)&msg_rddata->info;
				iov.iov_len = sizeof(struct data_info);
				KER_DEBUG(KERN_INFO"vmem thread: recvice rpy: read page");

				len = kernel_recvmsg(serhost->datasock, &recvdatamsg, &iov, 1,
							sizeof(struct data_info), 0);
				if(len == 0) {
					break;
				}
				if(len < 0 || len != sizeof(struct data_info)) {
					if(len == -ECONNREFUSED) {
						KER_DEBUG(KERN_INFO"vmem thread: recvice err");
					}
					continue;
				}
				msg_rddata->info.vpageaddr = msg_rpy.info.data.rpy_read.vpageaddr;
				KER_DEBUG(KERN_INFO"vmem thread: recvice read data len:%d", len);
				mutex_lock(&Devices->lshd_read_mutex);
				list_add_tail(&msg_rddata->ls_req, &Devices->lshd_read);
				mutex_unlock(&Devices->lshd_read_mutex);
				up(&Devices->read_semphore);
				break;
			}
			//heart beat
			case NETMSG_SER_REPLY_HEARTBEAT: {
				serhost->block_available = msg_rpy.info.data.rpy_heartbeat.blk_rest_available;
				break;
			}
		}
	}
err_device_ptr:
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
	return 0;
}
int SerSendThread(void *data) {
    struct kvec iov;
    struct server_host *serhost = (struct server_host *)data;
	struct msghdr sendmsg, senddatamsg;
	struct list_head *p = NULL, *next = NULL;
	struct list_head *pd = NULL, *dnext = NULL;
	struct netmsg_req *msg_req = NULL;
	struct netmsg_data *msg_wrdata = NULL;
    int len;

	memset(&msg_req, 0 ,sizeof(struct netmsg_req));
	memset(&sendmsg, 0, sizeof(struct msghdr));
	memset(&senddatamsg, 0, sizeof(struct msghdr));
	sendmsg.msg_name = (void *)&serhost->host_addr;
	sendmsg.msg_namelen = sizeof(struct sockaddr_in);
	senddatamsg.msg_name = (void *)&serhost->host_data_addr;
	senddatamsg.msg_namelen = sizeof(struct sockaddr_in);

    while (!kthread_should_stop()) {
		mutex_lock(&serhost->ptr_mutex);
		if(serhost->state == CLIHOST_STATE_CLOSED || !serhost->sock) {
			mutex_unlock(&serhost->ptr_mutex);
			break;
		}
		mutex_unlock(&serhost->ptr_mutex);
		msg_req = NULL;
		down(&serhost->send_sem);
		mutex_lock(&serhost->lshd_req_msg_mutex);
		list_for_each_safe(p, next, &serhost->lshd_req_msg) {
			msg_req = list_entry(p, struct netmsg_req, ls_reqmsg);
			break;
		}
		mutex_unlock(&serhost->lshd_req_msg_mutex);
		if(!msg_req) {
			break;
		}

        iov.iov_base = (void *)&msg_req->info;
        iov.iov_len = sizeof(struct req_info);
        len = kernel_sendmsg(serhost->sock, &sendmsg, &iov, 1, sizeof(struct req_info));
        if (len != sizeof(struct req_info)) {
            KER_DEBUG(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%ld\n",
                    len, sizeof(struct req_info));
            if (len == -ECONNREFUSED) {
                KER_DEBUG(KERN_ALERT "Receive Port Unreachable packet!\n");
            }
            //break;
        }
        KER_DEBUG(KERN_ALERT "kernel_sendmsg: len=%d\n", len);
		//if request is write
		if(msg_req->info.msgID == NETMSG_CLI_REQUEST_WRITE) {
			msg_wrdata = NULL;
			mutex_lock(&serhost->lshd_wrdata_mutex);
			list_for_each_safe(pd, dnext, &serhost->lshd_wrdata) {
				msg_wrdata = list_entry(pd, struct netmsg_data, ls_req);
				break;
			}
			mutex_unlock(&serhost->lshd_wrdata_mutex);
			if(msg_wrdata) {
				iov.iov_base = (void *)&msg_wrdata->info;
				iov.iov_len = sizeof(struct data_info);
				len = kernel_sendmsg(serhost->datasock, &senddatamsg, &iov, 1, sizeof(struct data_info));
				if (len != sizeof(struct data_info)) {
					KER_DEBUG(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%ld\n",
								len, sizeof(struct data_info));
					if (len == -ECONNREFUSED) {
						KER_DEBUG(KERN_ALERT "Receive Port Unreachable packet!\n");
					}
				}
			}
			mutex_lock(&serhost->lshd_wrdata_mutex);
			list_del(pd);
			mutex_unlock(&serhost->lshd_wrdata_mutex);
			kmem_cache_free(serhost->slab_netmsg_data, msg_wrdata);
		}

		mutex_lock(&serhost->lshd_req_msg_mutex);
		list_del(p);
		mutex_unlock(&serhost->lshd_req_msg_mutex);
		kmem_cache_free(serhost->slab_netmsg_req, msg_req);

    }
	if(serhost->sock) {
		kernel_sock_shutdown(serhost->sock, SHUT_RDWR);
	}
	if(serhost->datasock) {
		kernel_sock_shutdown(serhost->datasock, SHUT_RDWR);
	}
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}

    return 0;
}

int vmem_serhost_init(struct server_host *serhost) {
    int ret = KERERR_SUCCESS;
	int sockaddrlen = sizeof(struct sockaddr);

    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(serhost->sock));
    if (ret < KERERR_SUCCESS) {
        KER_DEBUG(KERN_ALERT "TCP create sock err, err=%d\n", ret);
		ret = KERERR_CREATE_SOCKET;
        goto create_error;
    }
    serhost->sock->sk->sk_reuse = 1;
    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(serhost->datasock));
    if (ret < KERERR_SUCCESS) {
        KER_DEBUG(KERN_ALERT "TCP create sock err, err=%d\n", ret);
		ret = KERERR_CREATE_SOCKET;
        goto create_data_error;
    }
    serhost->sock->sk->sk_reuse = 1;

    ret = bind_to_device(serhost->sock, VMEM_IF_NAME);
    if (ret < KERERR_SUCCESS) {
        KER_DEBUG(KERN_ALERT "Bind to %s err, err=%d\n", VMEM_IF_NAME, ret);
		ret = KERERR_SOCKET_BIND; 
        goto bind_error;
    }
    ret = bind_to_device(serhost->datasock, VMEM_IF_NAME);
    if (ret < KERERR_SUCCESS) {
        KER_DEBUG(KERN_ALERT "Bind to %s err, err=%d\n", VMEM_IF_NAME, ret);
		ret = KERERR_SOCKET_BIND; 
        goto bind_data_error;
    }

    ret = connect_to_addr(serhost->sock, serhost, SERHOST_LISTEN_PORT);
    if (ret < KERERR_SUCCESS) {
        KER_DEBUG(KERN_ALERT "sock connect err, err=%d\n", ret);
		ret = KERERR_SOCKET_CONNECT;
        goto connect_error;
    }
    ret = connect_to_addr(serhost->datasock, serhost, DATA_PORT);
    if (ret < KERERR_SUCCESS) {
        KER_DEBUG(KERN_ALERT "sock connect err, err=%d\n", ret);
		ret = KERERR_SOCKET_CONNECT;
        goto connect_error;
    }
	kernel_getpeername(serhost->sock, (struct sockaddr *)&serhost->host_addr, &sockaddrlen);
	kernel_getpeername(serhost->datasock, (struct sockaddr *)&serhost->host_data_addr, &sockaddrlen);
	//init mutex, list_head and slab
	mutex_init(&serhost->ptr_mutex);
	mutex_init(&serhost->lshd_req_msg_mutex);
	mutex_init(&serhost->lshd_wrdata_mutex);
	INIT_LIST_HEAD(&serhost->lshd_req_msg);
	INIT_LIST_HEAD(&serhost->lshd_wrdata);
	serhost->slab_netmsg_req = Devices->slab_netmsg_req;
	serhost->slab_netmsg_data = Devices->slab_netmsg_data;
	serhost->state = CLIHOST_STATE_CONNECTED;
	sema_init(&serhost->send_sem, 0);
	//create server send thread
	serhost->SerSendThread = kthread_run(SerSendThread, (void *)serhost, "Server Send thread");
    if (IS_ERR(serhost->SerSendThread)) {
        KER_DEBUG(KERN_ALERT "create sendmsg thread err, err=%ld\n",
                PTR_ERR(serhost->SerSendThread));
		ret = KERERR_CREATE_THREAD;
        goto thread_error;
    }
	//create server recv thread
	serhost->SerRecvThread = kthread_run(SerRecvThread, (void *)serhost, "Server Recv thread");
    if (IS_ERR(serhost->SerRecvThread)) {
        KER_DEBUG(KERN_ALERT "create recvmsg thread err, err=%ld\n",
                PTR_ERR(serhost->SerRecvThread));
		ret = KERERR_CREATE_THREAD;
        goto thread_error;
    }
    return ret;

thread_error:
connect_error:
bind_data_error:
bind_error:
	if(serhost->datasock) {
		sock_release(serhost->datasock);
		serhost->sock = NULL;
	}
create_data_error:
	if(serhost->sock) {
		sock_release(serhost->sock);
		serhost->sock = NULL;
	}
create_error:
    return ret;
}

int vmem_daemon(void *data) {
	struct vmem_dev * pdev = (struct vmem_dev *)data;
	int ret = KERERR_SUCCESS;
	unsigned sumpage = 0, sumblk = 0, nIndex = 0;
	while(!kthread_should_stop()) {
        schedule_timeout_interruptible(CALCULATE_PERIOD * HZ);
		for(nIndex = 0, sumpage = 0, sumblk = 0; nIndex < BLK_NUM_MAX; nIndex++) {
			if(pdev->addr_entry[nIndex].inuse) {
				sumblk++;
				sumpage += pdev->addr_entry[nIndex].inuse_page;
			}
		}
		KER_DEBUG(KERN_INFO"sumpage=%d, sumblk=%d\n", sumpage, sumblk);
		//memory over upper limit
		if(sumpage >= (unsigned int)(3 * ((sumblk * VPAGE_NUM_IN_BLK) >> 2))) {
			struct list_head *p = NULL;
			struct server_host *serhost = NULL; 
			KER_DEBUG(KERN_INFO"over upper limit\n");
			//find a available existing server
			mutex_lock(&Devices->lshd_serhost_mutex);
			list_for_each(p, &Devices->lshd_serhost) {
				serhost = list_entry(p, struct server_host, ls_serhost);
				if(serhost->block_available > 0) {
					break;
				}
				else {
					serhost = NULL;
				}
			}
			mutex_unlock(&Devices->lshd_serhost_mutex);
			//find one
			if(serhost) {
				struct netmsg_req * msg_req = NULL;
				KER_DEBUG(KERN_INFO"find a server\n");
				//find a available existing server
				msg_req = (struct netmsg_req *)kmem_cache_alloc(serhost->slab_netmsg_req, GFP_USER);
				memset((void *)msg_req, 0, sizeof(struct netmsg_req));
				msg_req->info.msgID = NETMSG_CLI_REQUEST_ALLOC_BLK;
				msg_req->info.data.req_alloc_blk.blknum = 1;
				mutex_lock(&serhost->lshd_req_msg_mutex);
				list_add_tail(&msg_req->ls_reqmsg, &serhost->lshd_req_msg);
				KER_DEBUG(KERN_INFO"add msg in server\n");
				mutex_unlock(&serhost->lshd_req_msg_mutex);
				up(&serhost->send_sem);
			}
			continue;
		}
		//memory below lower limit
		if(sumpage <= (unsigned int)(((sumblk * VPAGE_NUM_IN_BLK) >> 2))) {
			KER_DEBUG(KERN_INFO"over lower limit\n");
			continue;
		}
	}
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
	return ret;
}
