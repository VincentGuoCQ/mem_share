#define VMEM

#include "common.h"
#include "userspace/errors.h"
#include "userspace/msgfmt.h"

extern struct vmem_dev *Devices;

void IP_convert(struct in_addr *ip, unsigned char *str, unsigned int buflen) {
	snprintf(str, buflen, "%d.%d.%d.%d", ((unsigned char *)&(ip->s_addr))[0], ((unsigned char *)&(ip->s_addr))[1], ((unsigned char *)&(ip->s_addr))[2], ((unsigned char *)&(ip->s_addr))[3]);
}

static ssize_t serhost_state_show(struct device *dev, struct device_attribute *attr, char *buf) {
	char *out = buf;
	struct list_head *p = NULL;
	struct server_host *ps = NULL;
	char IPaddr[IP_ADDR_LEN];

	if(!Devices) {
		return 0;
	}
	
	out += sprintf(out, "Server Name\t\tIP Address\t\t Block Num\n");
	out += sprintf(out, "----------------------------------\n");
	
	mutex_lock(&Devices->lshd_avail_mutex);
	list_for_each(p, &Devices->lshd_available) {
		ps = list_entry(p, struct server_host, ls_available);
		IP_convert(&ps->host_addr, IPaddr, IP_ADDR_LEN);
		out += sprintf(out, "%s\t\t%s\t\t%d\n", ps->host_name, IPaddr, ps->block_num);
	}
	mutex_unlock(&Devices->lshd_avail_mutex);
	return out - buf;
}
static DEVICE_ATTR_RO(serhost_state);

static ssize_t serhost_op_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	struct MsgCliOp * cliop = NULL;
	struct server_host *serHost = NULL;
	char IPaddr[IP_ADDR_LEN];
	struct list_head *p = NULL;
	struct server_host *ps = NULL;

	if(count != sizeof(struct MsgCliOp)) {
		printk(KERN_NOTICE"vmem:%s:illegal input\n", __FUNCTION__);
		return 0;
	}
	cliop = (struct MsgCliOp *)kmalloc(sizeof(struct MsgCliOp), GFP_KERNEL);
	memcpy(cliop, buf, count);
	IP_convert(&cliop->info.addser.host_addr, IPaddr, IP_ADDR_LEN);
	printk(KERN_NOTICE"name:%s,addr:%s", cliop->info.addser.host_name, IPaddr);
	switch(cliop->op) {
		case CLIHOST_OP_ADD_SERHOST:
			printk(KERN_NOTICE"server add\n");
			//allocate memory and copy to memory
			serHost = (struct server_host *)kmem_cache_alloc(Devices->slab_server_host, GFP_KERNEL);
			memset(serHost, 0, sizeof(struct server_host));
			memcpy(serHost->host_name, cliop->info.addser.host_name, HOST_NAME_LEN);
			memcpy(&serHost->host_addr, &cliop->info.addser.host_addr, sizeof(struct in_addr));
			memcpy(&serHost->block_num, &cliop->info.addser.block_num, sizeof(unsigned int));
			//search for existing
			mutex_lock(&Devices->lshd_avail_mutex);
			list_for_each(p, &Devices->lshd_available) {
				ps = list_entry(p, struct server_host, ls_available);
				if(!memcmp(&ps->host_addr, &serHost->host_addr, sizeof(struct in_addr))) {
					break;
				}
			}
			mutex_unlock(&Devices->lshd_avail_mutex);

			//add to list
			if(p == &Devices->lshd_available) {
				mutex_lock(&Devices->lshd_avail_mutex);
				list_add_tail(&serHost->ls_available, &Devices->lshd_available);
				mutex_unlock(&Devices->lshd_avail_mutex);
			}
			else {
				goto err_ser_exit;
			}
			break;
	}

	kfree(cliop);
	return count;
err_ser_exit:
	return ERR_VMEM_HOST_EXIST;
}
static DEVICE_ATTR_WO(serhost_op);

int create_sysfs_file(struct device *dev) {
	int ret = ERR_SUCCESS;
	
	ret = device_create_file(dev, &dev_attr_serhost_state);
	if (ret) {
		printk(KERN_NOTICE"vmem:create sysfs file error: %d", ret);
		ret = ERR_VMEM_CREATE_FILE;
		goto err_sys_create_serhost_state;
	}

	ret = device_create_file(dev, &dev_attr_serhost_op);
	if (ret) {
		printk(KERN_NOTICE"vmem:create sysfs file error: %d", ret);
		ret = ERR_VMEM_CREATE_FILE;
		goto err_sys_create_serhost_op;
	}

	return ret;

err_sys_create_serhost_op:
	device_create_file(dev, &dev_attr_serhost_state);
err_sys_create_serhost_state:
	return ret;
}
void delete_sysfs_file(struct device *dev) {
	device_remove_file(dev, &dev_attr_serhost_state);
	device_remove_file(dev, &dev_attr_serhost_op);
}
