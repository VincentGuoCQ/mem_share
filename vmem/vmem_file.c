#include "../include.h"
#include "../kererr.h"
#include "../common.h"
#include "vmem_common.h"
#include "userspace/errors.h"
#include "../net_msg.h"

int write_swap(const char __user *buf, size_t count, loff_t *pos) {
	struct file *fp = NULL;
	mm_segment_t fs;
	fp = filp_open(SWAP_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if(IS_ERR(fp)) {
		KER_DEBUG(KERN_INFO"open swap file err\n");
		return KERERR_OPEN_FILE;
	}
	fs =get_fs();
	set_fs(KERNEL_DS);
	vfs_write(fp, buf, count, pos);
	filp_close(fp, NULL);
	KER_DEBUG(KERN_INFO"write to swap file\n");
	return count;
}
int read_swap(char __user *buf, size_t count, loff_t *pos) {
	struct file *fp = NULL;
	mm_segment_t fs;
	fp = filp_open(SWAP_FILE, O_RDONLY, 0644);
	if(IS_ERR(fp)) {
		KER_DEBUG(KERN_INFO"read swap file err\n");
		return KERERR_OPEN_FILE;
	}
	fs =get_fs();
	set_fs(KERNEL_DS);
	vfs_read(fp, buf, count, pos);
	filp_close(fp, NULL);
	KER_DEBUG(KERN_INFO"read from swap file\n");
	return count;
}
