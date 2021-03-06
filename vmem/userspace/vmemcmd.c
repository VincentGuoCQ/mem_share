#define VMEM

#include "vmemcmd.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "climsgfmt.h"
#include "debug.h"
#include "errors.h"
#include "vmemcmn.h"
#include <fcntl.h>
#include <unistd.h>

int rdwt_sysfs_attribute(const char *attr_path, char *rdbuf, unsigned int rdsize, char *wtbuf, unsigned int wtsize) {
	int fd;
	int length;

	fd = open(attr_path, O_RDWR | O_SYNC);
	if (fd < 0) {
		PRINT_INFO("error opening attribute %s\n", attr_path);
		return -1;
	}

	length = write(fd, wtbuf, wtsize);
	if (length < 0) {
		PRINT_INFO("error writing to attribute %s\n", attr_path);
		close(fd);
		return -1;
	}

	length = read(fd, rdbuf, rdsize);
	if (length != rdsize) {
		PRINT_INFO("error reading from attribute %s\n", attr_path);
		PRINT_INFO("%d\n", length);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}
int read_sysfs_attribute(const char *attr_path, char *buf, unsigned int size) {
	int fd;
	int length;

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		PRINT_INFO("error opening attribute %s\n", attr_path);
		return -1;
	}
	memset(buf, 0, size);
	length = read(fd, buf, size);
	if (length != size) {
		PRINT_INFO("error reading from attribute %s\n", attr_path);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}
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

int vmem_add_server(int argc, char *argv[]) {
	int opt = 0;
	char *SerName = NULL, *SerAddr = NULL, *SerBlockNum = NULL;
	struct MsgCliOp * pCli= (struct MsgCliOp *)malloc(sizeof(struct MsgCliOp));
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	memset(pCli, 0, sizeof(struct MsgCliOp));
	memset(path, 0, SYSFS_PATH_MAX);
	
	DEBUG_INFO("reset args:%s", argv[0]);
	//option parse
	for(;;) {
		opt = getopt_long(argc, argv, "n:a:b:", addser_opt, NULL);
		if(-1 == opt) {
			break;
		}
		
		switch(opt) {
			case 'n':
				DEBUG_INFO("server name:%s", optarg);
				SerName = optarg;
				break;
			case 'a':
				DEBUG_INFO("server address:%s", optarg);
				SerAddr = optarg;
				break;
			case 'b':
				DEBUG_INFO("block num:%s", optarg);
				SerBlockNum = optarg;
				break;

			default:
				PRINT_INFO("option error:invalid option\n");
		}
	}
	if(NULL == SerAddr) {
		PRINT_INFO("argument error: server name or address missing\n");
		ret = ERR_CLI_ARG_MISSING; 
		goto err_args;
	}

	//copy argument to structure
//	if(strlen(SerName) >= HOST_NAME_LEN) {
//		PRINT_INFO("argument error: sername too long\n");
//		ret = ERR_CLI_ARG_ILLEGAL;
//		goto err_args;
//	}
	//memcpy(pCli->info.addser.host_name, SerName, strlen(SerName));
	if(inet_aton(SerAddr, &pCli->info.addser.host_addr) == 0) {
		PRINT_INFO("argument error: IP address illegal\n");
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
//	if((pCli->info.addser.block_num = atoi(SerBlockNum)) == 0) {
//		PRINT_INFO("argument error: IP address illegal\n");
//		ret = ERR_CLI_ARG_ILLEGAL;
//		goto err_args;
//	}
	pCli->op = CLIHOST_OP_ADD_SERHOST;

	//write to file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_OP_PATH);
	write_sysfs_attribute(path, (char *)pCli, sizeof(struct MsgCliOp));

err_args:
	free(pCli);
	return ret;
}

int vmem_print_server(int argc, char *argv[]) {
	char path[SYSFS_PATH_MAX];
	memset(path, 0, SYSFS_PATH_MAX);
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_PRISER_PATH);

	print_sysfs_attribute(path);
	return 0;
}

int vmem_print_block(int argc, char *argv[]) {
	char path[SYSFS_PATH_MAX];
	memset(path, 0, SYSFS_PATH_MAX);
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_PRIBLK_PATH);
	
	print_sysfs_attribute(path);
	return 0;
}

int vmem_delete_server(int argc, char *argv[]) {
	int opt = 0;
	struct MsgCliOp * pCli= (struct MsgCliOp *)malloc(sizeof(struct MsgCliOp));
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	memset(pCli, 0, sizeof(struct MsgCliOp));
	memset(path, 0, SYSFS_PATH_MAX);

	for(;;) {
		opt = getopt_long(argc, argv, "ia", delser_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'i': {
				DEBUG_INFO("delete inuse server");
				pCli->op = CLIHOST_OP_DEL_SERHOST_INUSE;  
				break;
			}
			case 'a': {
				DEBUG_INFO("delete available server");
				pCli->op = CLIHOST_OP_DEL_SERHOST_AVAIL;  
				break;
			}
		}
	}

	//write to file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_OP_PATH);
	write_sysfs_attribute(path, (char *)pCli, sizeof(struct MsgCliOp));
	return ret;
}
int vmem_map_local(int argc, char *argv[]) {
	int opt = 0;
	char *blknum = NULL;
	struct MsgCliOp * pCli= (struct MsgCliOp *)malloc(sizeof(struct MsgCliOp));
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	memset(pCli, 0, sizeof(struct MsgCliOp));
	memset(path, 0, SYSFS_PATH_MAX);

	//option parse
	for(;;) {
		opt = getopt_long(argc, argv, "n:", maplocal_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'n':
				DEBUG_INFO("block num:%s", optarg);
				blknum = optarg;
				break;
		}
	}
	if(NULL == blknum) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	
	//copy argument to structure
	if((pCli->info.maplocal.block_num = atoi(blknum)) == 0) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	pCli->op = CLIHOST_OP_MAP_LOCAL;
	
	//write to file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_OP_PATH);
	write_sysfs_attribute(path, (char *)pCli, sizeof(struct MsgCliOp));

err_args:
	free(pCli);
	return ret;
}
int vmem_mod_server(int argc, char *argv[]) {
	int opt = 0;
	char *SerAddr = NULL, *SerBlockNum = NULL;
	struct MsgCliOp * pCli= (struct MsgCliOp *)malloc(sizeof(struct MsgCliOp));
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	memset(pCli, 0, sizeof(struct MsgCliOp));
	memset(path, 0, SYSFS_PATH_MAX);
	
	DEBUG_INFO("reset args:%s", argv[0]);
	//option parse
	for(;;) {
		opt = getopt_long(argc, argv, "a:b:", modser_opt, NULL);
		if(-1 == opt) {
			break;
		}
		
		switch(opt) {
			case 'a':
				DEBUG_INFO("server address:%s", optarg);
				SerAddr = optarg;
				break;
			case 'b':
				DEBUG_INFO("block num:%s", optarg);
				SerBlockNum = optarg;
				break;

			default:
				PRINT_INFO("option error:invalid option\n");
		}
	}
	if( NULL == SerAddr || NULL == SerBlockNum) {
		PRINT_INFO("argument error: server name or address missing\n");
		ret = ERR_CLI_ARG_MISSING; 
		goto err_args;
	}

	//copy argument to structure
	if(inet_aton(SerAddr, &pCli->info.modser.host_addr) == 0) {
		PRINT_INFO("argument error: IP address illegal\n");
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	if((pCli->info.modser.block_num = atoi(SerBlockNum)) == 0) {
		PRINT_INFO("argument error: IP address illegal\n");
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	pCli->op = CLIHOST_OP_MOD_SERHOST;

	//write to file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_OP_PATH);
	write_sysfs_attribute(path, (char *)pCli, sizeof(struct MsgCliOp));

err_args:
	free(pCli);
	return ret;
}
