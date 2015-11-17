#ifndef MSGFMT_H
#define MSGFMT_H

#define HOST_NAME_LEN			32

#ifdef VMEM

#define CLIHOST_OP_ADD_SERHOST		0x1
#define CLIHOST_OP_DEL_SERHOST		0x2
#define CLIHOST_OP_MOD_SERHOST		0x4

struct MsgCliOp {
	unsigned int op;
	union {
		struct {
			char host_name[HOST_NAME_LEN];
			struct in_addr host_addr;
			unsigned int block_num;
		} addser;
	} info;
};

#endif

#ifdef MEMPOOL

#define SERHOST_OP_ADD_BLK		0x01

struct MsgSerOp {
	unsigned int op;
	union {
		struct {
			unsigned int block_num;
		} addblk;
	} info;
};
#endif
#endif //MSGFMT_H
