#ifndef NET_MSG_H
#define NET_MSG_H

#define BLK_MAX_PER_REQ	(1UL << 2)

#define NETMSG_CLI_REQUEST_ALLOC_BLK	0x1
#define NETMSG_CLI_REQUEST_FREE_BLK		0x2
#define NETMSG_CLI_REQUEST_READ			0x3
#define NETMSG_CLI_REQUEST_WRITR		0x4

struct netmsg_req {
	struct list_head ls_reqmsg;
	unsigned int msgID;
	union {
		struct {
			unsigned int blknum;
		} req_alloc_blk;
		struct {
			unsigned int blknum;
			struct {
				unsigned int blkIndex;
			} blk_table[BLK_MAX_PER_REQ];
		} req_free_blk;
		struct {
			unsigned int blkIndex;
			unsigned int offset;
		} req_read;
		struct {
			unsigned int blkIndex;
			unsigned int offset;
		} req_write;
	} info;
};

#define NETMSG_SER_REPLY_ALLOC_BLK		0x1
#define NETMSG_SER_REPLY_ERR			0x2

struct netmsg_rpy {
	struct list_head ls_rpymsg;
	unsigned int msgID;
	union {
		struct {
			unsigned int blk_alloc;
			unsigned int blk_rest_available;
			struct {
				unsigned int remoteIndex;
				unsigned long remoteaddr;
			}blkinfo[BLK_MAX_PER_REQ];
		}rpyblk;
		struct {
			unsigned int errId;
		}rpyerr;
		struct {
			unsigned int blkIndex;
			unsigned int offset;
			unsigned int writebyte;
		} rpy_write;
		struct {
			unsigned int blkIndex;
			unsigned int offset;
		} rpy_read;
	} info;
};
#endif //NET_MSG_H
