#ifndef MSGFMT_H
#define MSGFMT_H

#define SERHOST_OP_ADD_BLK		0x01

struct MsgSerOp {
	unsigned int op;
	union {
		struct {
			unsigned int block_num;
		} addblk;
	} info;
};

#endif //MSGFMT_H
