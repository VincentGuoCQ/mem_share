#ifndef VMEM_COMMAND_H
#define VMEM_COMMAND_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

int vmem_add_server(int argc, char *argv[]);
int vmem_mod_server(int argc, char *argv[]);
int vmem_print_server(int argc, char *argv[]);
int vmem_print_block(int argc, char *argv[]);
int vmem_delete_server(int argc, char *argv[]);
int vmem_map_local(int argc, char *argv[]);
int vmem_alloc_page(int argc, char *argv[]);
int vmem_free_page(int argc, char *argv[]);
int vmem_write_page(int argc, char *argv[]);
int vmem_read_page(int argc, char *argv[]);

static const struct option addser_opt [] = {
	{"name",	required_argument,	NULL,	'n'},
	{"addr",	required_argument,	NULL,	'a'},
	{"blk",		required_argument,	NULL,	'b'},
	{NULL,	0,	NULL,	0}
};
static const struct option modser_opt [] = {
	{"addr",	required_argument,	NULL,	'a'},
	{"blk",		required_argument,	NULL,	'b'},
	{NULL,	0,	NULL,	0}
};
static const struct option maplocal_opt [] = {
	{"num",		required_argument,	NULL,	'n'},
	{NULL,	0,	NULL,	0}
};
static const struct option allocpage_opt [] = {
	{"num",		required_argument,	NULL,	'n'},
	{NULL,	0,	NULL,	0}
};
static const struct option freepage_opt [] = {
	{"num",		required_argument,	NULL,	'n'},
	{"addr",	required_argument,	NULL,	'a'},
	{NULL,	0,	NULL,	0}
};
static const struct option readpage_opt [] = {
	{"addr",	required_argument,	NULL,	'a'},
	{NULL,	0,	NULL,	0}
};
static const struct option writepage_opt [] = {
	{"addr",	required_argument,	NULL,	'a'},
	{"data",	required_argument,	NULL,	'd'},
	{NULL,	0,	NULL,	0}
};
static const struct option delser_opt [] = {
	{"inuse",	no_argument,	NULL,	'i'},
	{"avail",	no_argument,	NULL,	'a'},
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
		.name  = "modser",
		.fn    = vmem_mod_server,
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
		.name  = "priblk",
		.fn	   = vmem_print_block,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "delser",
		.fn	   = vmem_delete_server,
		.help  = NULL,
		.usage = NULL
	},
	{
		.name  = "maplocal",
		.fn	   = vmem_map_local,
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
		.name  = "freepage",
		.fn	   = vmem_free_page,
		.help  = NULL,
		.usage = NULL,
	},
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

#define PRINT_BUF_SIZE 100

#endif //VMEM_COMMAND_H
