#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include "errors.h"
#include "vmemcmn.h"
#include "debug.h"
#include "../../common.h"

int vmem_write_page(int argc, char *argv[]);
int vmem_read_page(int argc, char *argv[]);
int vmem_alloc_page(int argc, char *argv[]);

#define PRINT_BUF_SIZE 100
struct MsgMemAlloc {
	unsigned int vpagenum;
};

struct MsgMemRet {
	unsigned int vpagenum;
	unsigned long vpageaddr[VPAGE_PER_ALLOC];
};
static const struct option writepage_opt [] = {
	{"addr",	required_argument,	NULL,	'a'},
	{"num",		required_argument,	NULL,	'n'},
	{"data",	required_argument,	NULL,	'd'},
	{NULL,	0,	NULL,	0}
};

static const struct option readpage_opt [] = {
	{"addr",	required_argument,	NULL,	'a'},
	{"num",		required_argument,	NULL,	'n'},
	{NULL,	0,	NULL,	0}
};

static const struct option allocpage_opt [] = {
	{"num",		required_argument,	NULL,	'n'},
	{NULL,	0,	NULL,	0}
};
struct command {
	const char *name;
	int (*fn)(int argc, char *argv[]);
	const char *help;
	void (*usage)(void);
};

static const struct command cmds[] = {
	{
		.name  = "writepage",
		.fn	   = vmem_write_page,
		.help  = NULL,
		.usage = NULL,
	},
	{
		.name  = "allocpage",
		.fn	   = vmem_alloc_page,
		.help  = NULL,
		.usage = NULL,
	},
	{
		.name  = "readpage",
		.fn	   = vmem_read_page,
		.help  = NULL,
		.usage = NULL,
	},
	{NULL, NULL, NULL, NULL}
};

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
int vmem_write_page(int argc, char *argv[]) {
	int fd;
	unsigned long length;
	off_t off;
	int opt = 0, nIndex = 0;
	unsigned char *buf;
	char *pageaddr = NULL, *data = NULL ,*pagenum = NULL;
	for(;;) {
		opt = getopt_long(argc, argv, "a:d:n:", writepage_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'a':
				printf("page address:%s\n", optarg);
				pageaddr = optarg;
				break;
			case 'd':
				printf("date:%s\n", optarg);
				data = optarg;
				break;
			case 'n':
				printf("page num:%s\n", optarg);
				pagenum = optarg;
				break;
		}
	}
	if(NULL == pageaddr || NULL == data || NULL == pagenum) {
		return -1;
	}
	posix_memalign((void **)&buf, 512, VPAGE_SIZE * strtol(pagenum, NULL, 10));
	memset(buf, 0, VPAGE_SIZE * strtol(pagenum, NULL, 10));

	if((off = strtol(pageaddr, NULL, 16)) < 0) {
		return -1;
	}
	memcpy(buf, data, strlen(data));
	fd = open("/dev/vmem", O_WRONLY);
	if (fd < 0) {
		printf("error opening attribute vmem\n");
		return -1;
	}
	length = pwrite(fd, buf, VPAGE_SIZE * strtol(pagenum, NULL, 10), off);
	if (length != VPAGE_SIZE * strtol(pagenum, NULL, 10)) {
		printf("error writing to file, length = %d\n", length);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int vmem_read_page(int argc, char *argv[]) {
	int fd;
	unsigned long length;
	off_t off;
	int opt = 0, nIndex = 0;
	char *pageaddr = NULL, *pagenum = NULL;
	unsigned char *data = NULL;

	for(;;) {
		opt = getopt_long(argc, argv, "a:n:", readpage_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'a':
				printf("page address:%s\n", optarg);
				pageaddr = optarg;
				break;
			case 'n':
				printf("page num:%s\n", optarg);
				pagenum = optarg;
				break;
		}
	}
	if(NULL == pageaddr || NULL == pagenum) {
		return -1;
	}

	posix_memalign((void **)&data, 512, VPAGE_SIZE * strtol(pagenum, NULL, 10));
	memset(data, 0, VPAGE_SIZE * strtol(pagenum, NULL, 10));
	if((off = strtol(pageaddr, NULL, 16)) < 0) {
		return -1;
	}
	fd = open("/dev/vmem", O_RDONLY);
	if (fd < 0) {
		printf("error opening attribute vmem\n");
		return -1;
	}
	length = pread(fd, data, VPAGE_SIZE * strtol(pagenum, NULL, 10), off);
	if (length <= 0) {
		printf("error writing to file, length = %d\n", length);
		close(fd);
		return -1;
	}
	printf("%s\n",data);
	close(fd);
	return 0;
}
int main (int argc, char *argv[]) {
	int i = 0, ret = 0;
	char *cmd = NULL;

	if(argc < 2) {
		printf("command missing\n");
		return 0; 
	}
	cmd = argv[1];
	for(i = 0; cmds[i].name != NULL; i++) {
		if(!strcmp(cmds[i].name, cmd))
		  break;
	}

	if(cmds[i].fn) {
		ret = cmds[i].fn(argc-1, argv+1);
	}
	else {
		printf("command error, please input correct command:%d\n", i);
	}
	if(0 != ret) {
		printf("command format or execute error\n");
	}
	return 0;
}
