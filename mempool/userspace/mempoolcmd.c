#define MEMPOOL

#include "mempoolcmd.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "msgfmt.h"
#include "debug.h"
#include "errors.h"
#include "mempoolcmn.h"
#include <fcntl.h>
#include <unistd.h>

int print_sysfs_attribute(const char *attr_path) {
	int fd;
	int length;
	char buf[PRINT_BUF_SIZE];

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		PRINT_INFO("error opening attribute %s\n", attr_path);
		return -1;
	}
	memset(buf, 0, PRINT_BUF_SIZE);
	length = read(fd, buf, PRINT_BUF_SIZE-1);
	while(length > 0) {
		printf("%s", buf);
		memset(buf, 0, PRINT_BUF_SIZE);
		length = read(fd, buf, PRINT_BUF_SIZE-1);
	}
	if (length < 0) {
		PRINT_INFO("error reading from attribute %s\n", attr_path);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}
int write_sysfs_attribute(const char *attr_path, const char *new_value, size_t len) {
	int fd;
	int length;

	fd = open(attr_path, O_WRONLY | O_SYNC);
	if (fd < 0) {
		PRINT_INFO("error opening attribute %s\n", attr_path);
		return -1;
	}
	length = write(fd, new_value, len);
	if (length < 0) {
		PRINT_INFO("error writing to attribute %s\n", attr_path);
	}
	close(fd);
	return length;
}


int mempool_add_block(int argc, char *argv[]) {
	int opt = 0;
	char *blknum = NULL;
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	struct MsgSerOp *pSer = (struct MsgSerOp *)malloc(sizeof(struct MsgSerOp));
	memset(pSer, 0, sizeof(struct MsgSerOp));
	memset(path, 0, SYSFS_PATH_MAX);

	//option parse
	for(;;) {
		opt = getopt_long(argc, argv, "n:", addblk_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'n':
				DEBUG_INFO("block num:%s", optarg);
				blknum = optarg;
				break;
			default:
				PRINT_INFO("option error:invalid option\n");
		}
	}

	if(NULL == blknum) {
		PRINT_INFO("argument error: block number missing\n");
		ret = ERR_CLI_ARG_MISSING;
		goto err_args;
	}
	//copy to structure
	if((pSer->info.addblk.block_num = atoi(blknum)) == 0) {
		PRINT_INFO("argument error: block number illegal\n");
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	pSer->op = SERHOST_OP_ADD_BLK;
	
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH, SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_MEMPOOLCFG_PATH);
	write_sysfs_attribute(path, (char *)pSer, sizeof(struct MsgSerOp));

err_args:
	free(pSer);
	return ret;
}
