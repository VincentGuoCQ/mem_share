#ifndef MEMPOOL_COMMAND_H
#define MEMPOOL_COMMAND_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

int mempool_add_block(int argc, char *argv[]);
int mempool_del_block(int argc, char *argv[]);
int mempool_print_client(int argc, char *argv[]);
int mempool_print_blk(int argc, char *argv[]);

static const struct option addblk_opt [] = {
	{"num",	required_argument,	NULL,	'n'},
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
		.name  = "addblk",
		.fn    = mempool_add_block,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "delcli",
		.fn    = mempool_del_block,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "pricli",
		.fn    = mempool_print_client,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "priblk",
		.fn    = mempool_print_blk,
		.help  = NULL,
		.usage = NULL
	},
	{NULL, NULL, NULL, NULL}
};

#define PRINT_BUF_SIZE 100

#endif //MEMPOOL_COMMAND_H
