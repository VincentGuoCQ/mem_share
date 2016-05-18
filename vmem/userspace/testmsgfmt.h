#ifndef TESTMSGFMT_H
#define TESTMSGFMT_H

#include "../../common.h"

#define HOST_NAME_LEN			32

#define CLIHOST_OP_ADD_SERHOST				0x1
#define CLIHOST_OP_DEL_SERHOST_AVAIL		0x2
#define CLIHOST_OP_DEL_SERHOST_INUSE		0x3
#define CLIHOST_OP_MOD_SERHOST				0x4
#define CLIHOST_OP_MAP_LOCAL				0x7

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
