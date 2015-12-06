#include "../include.h"
#include "../common.h"
#include "vmem_common.h"
#include <linux/kthread.h>
#include "../kererr.h"
#include "../net_msg.h"

extern struct vmem_dev *Devices;

static int bind_to_device(struct socket *sock, char *ifname, struct server_host *serhost) {
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

static int connect_to_addr(struct socket *sock, struct server_host *serhost) {
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

static int SerRecvThread(void *data) {
    struct kvec iov;
    struct server_host *serhost = (struct server_host *)data;
	struct msghdr msg;
	struct netmsg_rpy *msg_rpy = (struct netmsg_rpy *)kmalloc(sizeof(struct netmsg_rpy), GFP_USER);
	struct netmsg_data *msg_rddata = NULL;
	int len = 0;
	if(!Devices) {
		goto err_device_ptr;
	}
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
		mutex_lock(&serhost->ptr_mutex);
		if(!serhost->sock) {
			mutex_unlock(&serhost->ptr_mutex);
			break;
		}
		mutex_unlock(&serhost->ptr_mutex);
		memset(msg_rpy, 0, sizeof(struct netmsg_rpy));
		iov.iov_base = (void *)msg_rpy;
		iov.iov_len = sizeof(struct netmsg_rpy);

		len = kernel_recvmsg(serhost->sock, &msg, &iov, 1,
					sizeof(struct netmsg_rpy), MSG_DONTWAIT);
		//close of client
		if(len == 0) {
			break;
		}
		if(len < 0 || len != sizeof(struct netmsg_rpy)) {
			if(len == -ECONNREFUSED) {
				printk(KERN_INFO"vmem thread: recvice err");
			}
			continue;
		}
		printk(KERN_INFO"vmem thread: recvice netmsg_rpy:%d", msg_rpy->msgID);
		switch(msg_rpy->msgID) {
			//alloc block
			case NETMSG_SER_REPLY_ALLOC_BLK:{
				unsigned int  nIndex = 0, count = 0;
				printk(KERN_INFO"vmem thread: recvice rpy: alloc blk");
				for(nIndex = 0, count = 0; nIndex < BLK_NUM_MAX &&
							count < msg_rpy->info.rpyblk.blk_alloc; nIndex++) {
					if(FALSE == Devices->addr_entry[nIndex].inuse) {
						Devices->addr_entry[nIndex].entry.vmem.blk_remote_index =
							msg_rpy->info.rpyblk.blkinfo[count].remoteIndex;
						Devices->addr_entry[nIndex].entry.vmem.blk_remote_addr = 
							msg_rpy->info.rpyblk.blkinfo[count].remoteaddr;
						Devices->addr_entry[nIndex].entry.vmem.blk_size = BLK_SIZE; 
						Devices->addr_entry[nIndex].entry.vmem.serhost = serhost;
						Devices->addr_entry[nIndex].entry.vmem.inuse = TRUE;
						Devices->addr_entry[nIndex].remote = TRUE;
						Devices->addr_entry[nIndex].inuse = TRUE;
						count ++;
					}
				}
				serhost->block_inuse += count;
				serhost->block_available = msg_rpy->info.rpyblk.blk_rest_available;
				break;
			}
			//read page
			case NETMSG_SER_REPLY_READ: {
				msg_rddata = (struct netmsg_data *)kmem_cache_alloc(serhost->slab_netmsg_data, GFP_USER);
				memset(msg_rddata, 0, sizeof(struct netmsg_data));
				iov.iov_base = (void *)msg_rddata;
				iov.iov_len = sizeof(struct netmsg_data);

				len = kernel_recvmsg(serhost->sock, &msg, &iov, 1,
							sizeof(struct netmsg_data), MSG_DONTWAIT);
				if(len == 0) {
					break;
				}
				if(len < 0 || len != sizeof(struct netmsg_data)) {
					if(len == -ECONNREFUSED) {
						printk(KERN_INFO"vmem thread: recvice err");
					}
					continue;
				}
				msg_rddata->vpageaddr = msg_rpy->info.rpy_read.vpageaddr;
				printk(KERN_INFO"vmem thread: recvice read data len:%d", len);
				mutex_lock(&Devices->lshd_read_mutex);
				list_add_tail(&msg_rddata->ls_req, &Devices->lshd_read);
				mutex_unlock(&Devices->lshd_read_mutex);
				break;
			}
		}
	}
err_device_ptr:
	kfree(msg_rpy);
	kmem_cache_free(serhost->slab_netmsg_data, msg_rddata);
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
	return 0;
}
static int SerSendThread(void *data) {
    struct kvec iov;
    struct server_host *serhost = (struct server_host *)data;
	struct msghdr msg;
	struct list_head *p = NULL, *next = NULL;
	struct list_head *pd = NULL, *dnext = NULL;
	struct netmsg_req *msg_req = NULL;
	struct netmsg_data *msg_wrdata = NULL;
    int len;

	memset(&msg_req, 0 ,sizeof(struct netmsg_req));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

    while (!kthread_should_stop()) {
        schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
		mutex_lock(&serhost->ptr_mutex);
		if(!serhost->sock) {
			mutex_unlock(&serhost->ptr_mutex);
			break;
		}
		mutex_unlock(&serhost->ptr_mutex);
		msg_req = NULL;
		mutex_lock(&serhost->lshd_req_msg_mutex);
		list_for_each_safe(p, next, &serhost->lshd_req_msg) {
			msg_req = list_entry(p, struct netmsg_req, ls_reqmsg);
			break;
		}
		mutex_unlock(&serhost->lshd_req_msg_mutex);
		if(!msg_req) {
			continue;
		}
        iov.iov_base = (void *)msg_req;
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
		//if request is write
		if(msg_req->msgID == NETMSG_CLI_REQUEST_WRITE) {
			msg_wrdata = NULL;
			mutex_lock(&serhost->lshd_wrdata_mutex);
			list_for_each_safe(pd, dnext, &serhost->lshd_wrdata) {
				msg_wrdata = list_entry(pd, struct netmsg_data, ls_req);
				break;
			}
			mutex_unlock(&serhost->lshd_wrdata_mutex);
			if(msg_wrdata) {
				iov.iov_base = (void *)msg_wrdata;
				iov.iov_len = sizeof(struct netmsg_data);
				len = kernel_sendmsg(serhost->sock, &msg, &iov, 1, sizeof(struct netmsg_data));
				if (len != sizeof(struct netmsg_data)) {
					printk(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%ld\n",
								len, sizeof(struct netmsg_data));
					if (len == -ECONNREFUSED) {
						printk(KERN_ALERT "Receive Port Unreachable packet!\n");
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

        printk(KERN_ALERT "kernel_sendmsg: len=%d\n", len);
    }
//	if(serhost->sock) {
//		sock_release(serhost->sock);
//		serhost->sock = NULL;
//	}
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}

    return 0;
}

int vmem_net_init(struct server_host *serhost) {
    int ret = KERERR_SUCCESS;

    ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &(serhost->sock));
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "TCP create sock err, err=%d\n", ret);
		ret = KERERR_CREATE_SOCKET;
        goto create_error;
    }
    serhost->sock->sk->sk_reuse = 1;

    ret = bind_to_device(serhost->sock, VMEM_IF_NAME, serhost);

    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "Bind to %s err, err=%d\n", VMEM_IF_NAME, ret);
		ret = KERERR_SOCKET_BIND; 
        goto bind_error;
    }    
    ret = connect_to_addr(serhost->sock, serhost);
    if (ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "sock connect err, err=%d\n", ret);
		ret = KERERR_SOCKET_CONNECT;
        goto connect_error;
    }
	serhost->host_addr.sin_family = AF_INET;
	serhost->host_addr.sin_port = cpu_to_be16(SERHOST_LISTEN_PORT);
	ret = kernel_connect(serhost->sock, (struct sockaddr *)&serhost->host_addr, sizeof(struct sockaddr), 0);
	if(ret < KERERR_SUCCESS) {
        printk(KERN_ALERT "sock connect server err, err=%d\n", ret);
        //goto connect_error;
	}
	ret = KERERR_SUCCESS;
	//create server send thread
	serhost->SerSendThread = kthread_run(SerSendThread, (void *)serhost, "Server Send thread");
    if (IS_ERR(serhost->SerSendThread)) {
        printk(KERN_ALERT "create sendmsg thread err, err=%ld\n",
                PTR_ERR(serhost->SerSendThread));
		ret = KERERR_CREATE_THREAD;
        goto thread_error;
    }
	//create server recv thread
	serhost->SerRecvThread = kthread_run(SerRecvThread, (void *)serhost, "Server Recv thread");
    if (IS_ERR(serhost->SerRecvThread)) {
        printk(KERN_ALERT "create recvmsg thread err, err=%ld\n",
                PTR_ERR(serhost->SerRecvThread));
		ret = KERERR_CREATE_THREAD;
        goto thread_error;
    }
    return KERERR_SUCCESS;

thread_error:
connect_error:
bind_error:
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
		printk(KERN_INFO"sumpage=%d, sumblk=%d\n", sumpage, sumblk);
		//memory over upper limit
		if(sumpage >= (unsigned int)(3 * ((sumblk * VPAGE_NUM_IN_BLK) >> 2))) {
			struct list_head *p = NULL, *next = NULL;
			struct server_host *serhost = NULL; 
			printk(KERN_INFO"over upper limit\n");
			//find a available existing server
			mutex_lock(&Devices->lshd_inuse_mutex);
			list_for_each(p, &Devices->lshd_inuse) {
				serhost = list_entry(p, struct server_host, ls_inuse);
				if(serhost->block_available > 0) {
					break;
				}
				else {
					serhost = NULL;
				}
			}
			mutex_unlock(&Devices->lshd_inuse_mutex);
			//find one
			if(serhost) {
				struct netmsg_req * msg_req = NULL;
				printk(KERN_INFO"find a inuse server\n");
				//find a available existing server
				msg_req = (struct netmsg_req *)kmem_cache_alloc(serhost->slab_netmsg_req, GFP_USER);
				memset((void *)msg_req, 0, sizeof(struct netmsg_req));
				msg_req->msgID = NETMSG_CLI_REQUEST_ALLOC_BLK;
				msg_req->info.req_alloc_blk.blknum = 1;
				mutex_lock(&serhost->lshd_req_msg_mutex);
				list_add_tail(&msg_req->ls_reqmsg, &serhost->lshd_req_msg);
				printk(KERN_INFO"add msg in inuse server\n");
				mutex_unlock(&serhost->lshd_req_msg_mutex);
				continue;
			}
			//not find
			else {
				serhost = NULL;
			}
			//connect to a new server
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each_safe(p, next, &Devices->lshd_available) {
				serhost = list_entry(p, struct server_host, ls_available);
				list_del(p);
				break;
			}
			mutex_unlock(&Devices->lshd_avail_mutex);
			if(NULL == serhost) {
				continue;
			}

			ret = vmem_net_init(serhost);
			//if tcp to server established, add server to inuse list
			if(ret == KERERR_SUCCESS) {
				mutex_lock(&Devices->lshd_inuse_mutex);
				list_add_tail(&serhost->ls_inuse, &Devices->lshd_inuse);
				mutex_unlock(&Devices->lshd_inuse_mutex);
				printk(KERN_INFO"add server to inuse list\n");
			}
			//if tcp to server not established, delete server
			else {
				kmem_cache_free(Devices->slab_server_host, serhost);
			}
			continue;
		}
		//memory below lower limit
		if(sumpage <= (unsigned int)(((sumblk * VPAGE_NUM_IN_BLK) >> 2))) {
			printk(KERN_INFO"over lower limit");
			continue;
		}
	}
	while(!kthread_should_stop()) {
		schedule_timeout_interruptible(SCHEDULE_TIME * HZ);
	}
	return 0;
}
