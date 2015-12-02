#define VMEM

#include "vmemcmd.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "msgfmt.h"
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
	if( NULL == SerName || NULL == SerAddr || NULL == SerBlockNum) {
		PRINT_INFO("argument error: server name or address missing\n");
		ret = ERR_CLI_ARG_MISSING; 
		goto err_args;
	}

	//copy argument to structure
	if(strlen(SerName) >= HOST_NAME_LEN) {
		PRINT_INFO("argument error: sername too long\n");
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	memcpy(pCli->info.addser.host_name, SerName, strlen(SerName));
	if(inet_aton(SerAddr, &pCli->info.addser.host_addr) == 0) {
		PRINT_INFO("argument error: IP address illegal\n");
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	if((pCli->info.addser.block_num = atoi(SerBlockNum)) == 0) {
		PRINT_INFO("argument error: IP address illegal\n");
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
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
int vmem_alloc_page(int argc, char *argv[]) {
	int opt = 0, i = 0;
	char *pagenum = NULL;
	struct MsgMemAlloc memalloc;
	struct MsgMemRet memret;
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	memset(path, 0, SYSFS_PATH_MAX);
	memset(&memalloc, 0, sizeof(struct MsgMemAlloc));
	memset(&memret, 0, sizeof(struct MsgMemRet));

	//option parse
	for(;;) {
		opt = getopt_long(argc, argv, "n:", allocpage_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'n':
				DEBUG_INFO("page num:%s", optarg);
				pagenum = optarg;
				break;
		}
	}
	if(NULL == pagenum) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	
	//copy argument to structure
	if((memalloc.vpagenum = atoi(pagenum)) == 0) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	
	//write to file and read from file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_ALLOC_PATH);
	write_sysfs_attribute(path, (char *)&memalloc, sizeof(struct MsgMemAlloc));
	read_sysfs_attribute(path, (char *)&memret, sizeof(struct MsgMemRet));
	for(i = 0; i < memret.vpagenum; i++) {
		printf("page %d:%lx\n", i, memret.vpageaddr[i]);
	}
err_args:
	return ret;
}

int vmem_free_page(int argc, char *argv[]) {
	int opt = 0, nIndex = 0, argvdis = 0;
	char *pagenum = NULL, *vaddrbeg = NULL;
	struct MsgMemFree memfree;
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];

	memset(&memfree, 0, sizeof(struct MsgMemFree));
	memset(path, 0, SYSFS_PATH_MAX);

	//option parse
	for(;;) {
		opt = getopt_long(argc, argv, "n:a:", freepage_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'n':
				DEBUG_INFO("page num:%s", optarg);
				pagenum = optarg;
				break;
			case 'a':
				DEBUG_INFO("page addr:%s", optarg);
				vaddrbeg = optarg;
				break;
		}
	}
	if(NULL == pagenum) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	
	//copy argument to structure
	if((memfree.vpagenum = atoi(pagenum)) == 0) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	for(argvdis = 0; argvdis < argc; argvdis++) {
		if(*(argv+argvdis) == vaddrbeg)
		  break;
	}
	if(memfree.vpagenum > argc - argvdis) {
		ret = ERR_CLI_ARG_ILLEGAL;
		DEBUG_INFO("page addr not enough");
		goto err_args;
	}

	if(memfree.vpagenum > VPAGE_PER_FREE) {
		ret = ERR_CLI_ARG_ILLEGAL;
		DEBUG_INFO("page number over limit");
		goto err_args;
	}

	for(nIndex = 0; nIndex < memfree.vpagenum; nIndex++) {
		memfree.vpageaddr[nIndex] = strtol(*(argv+argvdis+nIndex), NULL, 16);
		DEBUG_INFO("addr %lx", memfree.vpageaddr[nIndex]);
	}
	//write to file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_FREE_PATH);
	write_sysfs_attribute(path, (char *)&memfree, sizeof(struct MsgMemFree));

err_args:
	return 0;
}

int vmem_write_page(int argc, char *argv[]) {
	int opt = 0, nIndex = 0;
	int ret = ERR_SUCCESS;
	struct MsgMemWrite *pmemwrite = (struct MsgMemWrite *)malloc(sizeof(struct MsgMemWrite)); 
	char *pageaddr = NULL, *data = NULL;
	char path[SYSFS_PATH_MAX];

	memset(path, 0, SYSFS_PATH_MAX);
	memset(pmemwrite, 0, sizeof(struct MsgMemWrite));

	for(;;) {
		opt = getopt_long(argc, argv, "a:d:", writepage_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'a':
				DEBUG_INFO("page address:%s", optarg);
				pageaddr = optarg;
				break;
			case 'd':
				DEBUG_INFO("date:%s", optarg);
				data = optarg;
				break;
		}
	}
	if(NULL == pageaddr || NULL == data) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}

	if((pmemwrite->vpageaddr = strtol(pageaddr, NULL, 16)) < 0) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	memcpy(pmemwrite->Data, data, strlen(data));
	//write to file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_WRITE_PATH);
	write_sysfs_attribute(path, (char *)pmemwrite, sizeof(struct MsgMemWrite));
	free(pmemwrite);

err_args:
	return 0;
}

int vmem_read_page(int argc, char *argv[]) {
	int opt = 0;
	char *pageaddr = NULL;
	int ret = ERR_SUCCESS;
	char path[SYSFS_PATH_MAX];
	struct MsgMemRead memread; 
	struct MsgMemReadRet *pmemreadret = (struct MsgMemReadRet *)malloc(sizeof(struct MsgMemReadRet)); 
	memset(path, 0, SYSFS_PATH_MAX);
	memset(pmemreadret, 0, sizeof(struct MsgMemReadRet));

	//option parse
	for(;;) {
		opt = getopt_long(argc, argv, "a:", readpage_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'a':
				DEBUG_INFO("page addr:%s", optarg);
				pageaddr = optarg;
				break;
		}
	}
	if(NULL == pageaddr) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	
	//copy argument to structure
	if((memread.vpageaddr = strtol(pageaddr, NULL, 16)) < 0) {
		ret = ERR_CLI_ARG_ILLEGAL;
		goto err_args;
	}
	
	//write to file and read from file
	snprintf(path, SYSFS_PATH_MAX, "%s/%s/%s/%s", SYSFS_MNT_PATH,
				SYSFS_BLKDEV_PATH, SYSFS_DEV_PATH, SYSFS_CLI_READ_PATH);
	write_sysfs_attribute(path, (char *)&memread, sizeof(struct MsgMemRead));
	read_sysfs_attribute(path, (char *)pmemreadret, sizeof(struct MsgMemReadRet));

	DEBUG_INFO("address:%lx", pmemreadret->vpageaddr);
	DEBUG_INFO("data:%s", pmemreadret->Data);
err_args:
	free(pmemreadret);
	return ret;
}
