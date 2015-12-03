#ifndef MSGFMT_H
#define MSGFMT_H

#include "../../common.h"

#define HOST_NAME_LEN			32

#define CLIHOST_OP_ADD_SERHOST				0x1
#define CLIHOST_OP_DEL_SERHOST_AVAIL		0x2
#define CLIHOST_OP_DEL_SERHOST_INUSE		0x3
#define CLIHOST_OP_MOD_SERHOST				0x4
#define CLIHOST_OP_MAP_LOCAL				0x7

struct MsgCliOp {
	unsigned int op;
	union {
		struct {
			char host_name[HOST_NAME_LEN];
			struct in_addr host_addr;
			unsigned int block_num;
		} addser;
		struct {
			struct in_addr host_addr;
			unsigned int block_num;
		} modser;
		struct {
			unsigned int block_num;
		} maplocal;
	} info;
};

struct MsgMemAlloc {
	unsigned int vpagenum;
};

struct MsgMemRet {
	unsigned int vpagenum;
	unsigned long vpageaddr[VPAGE_PER_ALLOC];
};

struct MsgMemFree {
	unsigned int vpagenum;
	unsigned long vpageaddr[VPAGE_PER_ALLOC];
};

struct MsgMemRead {
	unsigned long vpageaddr;
};

struct MsgMemReadRet {
	unsigned long vpageaddr;
	char Data[VPAGE_SIZE];
};

struct MsgMemWrite {
	unsigned long vpageaddr;
	char Data[VPAGE_SIZE];
};

#endif //MSGFMT_H
