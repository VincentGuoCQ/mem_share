#ifndef	COMMON_H
#define COMMON_H

#define VMEM_NAME				"vmem"
#define MEMPOOL_NAME			"mempool"
#define INVALIDATE_DELAY		30*HZ
#define KERNEL_SECTOR_SIZE		512

#define VPAGE_SIZE_SHIFT	10
#define VPAGE_SIZE			(1UL << VPAGE_SIZE_SHIFT)
#define BLK_SIZE_SHIFT		13
#define BLK_SIZE			(1UL << BLK_SIZE_SHIFT)
#define BLK_NUM_MAX_SHIFT	3
#define BLK_NUM_MAX		(1UL << BLK_NUM_MAX_SHIFT)

#define GET_BLK_INDEX(x)		(( x >> BLK_SIZE_SHIFT) & ((1UL <<(BLK_NUM_MAX_SHIFT))-1))
#define GET_VPAGE_INDEX(x)		(( x >> VPAGE_SIZE_SHIFT) & ((1UL <<(BLK_SIZE_SHIFT -VPAGE_SIZE_SHIFT))-1))

#define VPAGE_NUM_IN_BLK	(1UL << (BLK_SIZE_SHIFT - VPAGE_SIZE_SHIFT))

#define HOST_NAME_LEN		32
#define IP_ADDR_LEN			16

#define MAX_BLK_NUM_IN_MEMPOOL	(1UL << 3)

#define SERHOST_LISTEN_PORT	8000

#define SCHEDULE_TIME	0.5

#define TRUE	1
#define FALSE	0

#define ADDR_SPACE_LEN  BLK_NUM_MAX_SHIFT+BLK_SIZE_SHIFT

#define VPAGE_PER_ALLOC 4
#define VPAGE_PER_FREE 4

#endif // COMMON_H
