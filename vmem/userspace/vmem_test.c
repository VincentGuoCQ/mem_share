#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include "../../common.h"

int vmem_write_page(int argc, char *argv[]);
int vmem_read_page(int argc, char *argv[]);

static const struct option writepage_opt [] = {
	{"addr",	required_argument,	NULL,	'a'},
	{"data",	required_argument,	NULL,	'd'},
	{NULL,	0,	NULL,	0}
};

static const struct option readpage_opt [] = {
	{"addr",	required_argument,	NULL,	'a'},
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
		.name  = "readpage",
		.fn	   = vmem_read_page,
		.help  = NULL,
		.usage = NULL,
	},
	{NULL, NULL, NULL, NULL}
};

int vmem_write_page(int argc, char *argv[]) {
	int fd;
	int length;
	off_t off;
	int opt = 0, nIndex = 0;
	char buf[VPAGE_SIZE];
	char *pageaddr = NULL, *data = NULL;

	memset(buf, 0, VPAGE_SIZE);
	for(;;) {
		opt = getopt_long(argc, argv, "a:d:", writepage_opt, NULL);
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
		}
	}
	if(NULL == pageaddr || NULL == data) {
		return -1;
	}

	if((off = strtol(pageaddr, NULL, 16)) < 0) {
		return -1;
	}
	memcpy(buf, data, strlen(data));
	fd = open("/dev/vmem", O_WRONLY);
	if (fd < 0) {
		printf("error opening attribute vmem\n");
		return -1;
	}
	length = pwrite(fd, buf, VPAGE_SIZE, off);
	if (length != VPAGE_SIZE) {
		printf("error writing to file, length = %d\n", length);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int vmem_read_page(int argc, char *argv[]) {
	int fd;
	int length;
	off_t off;
	int opt = 0, nIndex = 0;
	char *pageaddr = NULL;
	char data[VPAGE_SIZE];

	memset(data, 0, VPAGE_SIZE);
	for(;;) {
		opt = getopt_long(argc, argv, "a:d:", readpage_opt, NULL);
		if(-1 == opt) {
			break;
		}

		switch(opt) {
			case 'a':
				printf("page address:%s\n", optarg);
				pageaddr = optarg;
				break;
		}
	}
	if(NULL == pageaddr) {
		return -1;
	}

	if((off = strtol(pageaddr, NULL, 16)) < 0) {
		return -1;
	}
	fd = open("/dev/vmem", O_RDONLY);
	if (fd < 0) {
		printf("error opening attribute vmem\n");
		return -1;
	}
	length = pread(fd, data, VPAGE_SIZE, off);
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
