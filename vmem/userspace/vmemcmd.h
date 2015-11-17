#ifndef VMEM_COMMAND_H
#define VMEM_COMMAND_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

int vmem_add_server(int argc, char *argv[]);
int vmem_print_server(int argc, char *argv[]);
int vmem_delete_server(int argc, char *argv[]);

static const struct option addser_opt [] = {
	{"name",	required_argument,	NULL,	'n'},
	{"addr",	required_argument,	NULL,	'a'},
	{"blk",		required_argument,	NULL,	'b'},
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
		.name  = "addser",
		.fn    = vmem_add_server,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "priser",
		.fn	   = vmem_print_server,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "delser",
		.fn	   = vmem_delete_server,
		.help  = NULL,
		.usage = NULL
	},
	{NULL, NULL, NULL, NULL}
};

#define PRINT_BUF_SIZE 100

#endif //VMEM_COMMAND_H
