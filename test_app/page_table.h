#ifndef PAGE_TABLE_H
#define PAGE_TABLE_H

struct list_head {
	struct list_head *next, *prev;
};

typedef struct {unsigned long vpde_entry;} vpgd_t;
typedef struct {unsigned long vpte_entry;} vpde_t;
typedef struct {
	struct list_head ls;
	unsigned long vpg_entry;
} vpte_t;

#define PTE_SHIFT	3
#define PDE_SHIFT	3

#define PG_PRESENT (1UL << 9)
#define PG_SWAP (1UL << 8)
#define PG_WR (1UL << 7)
#define PG_RD (1UL << 6)
#define PG_EXCUTE (1UL << 5)

void init_vpde(vpgd_t * ppgd);
void destroy_vpde(vpgd_t * ppgd);
void print_vpde(vpgd_t *ppgd);
#define VOFFSET_MASK ((1UL << VPAGE_SIZE_SHIFT)-1)
#define VPAGE_MASK (~((1UL << VPAGE_SIZE_SHIFT)-1))
#define ADDR_TO_PAGE_INDEX(ADDR)	((ADDR >> VPAGE_SIZE_SHIFT) & ((1UL <<(PTE_SHIFT+PDE_SHIFT))-1))
#define PAGE_TO_PDE(PAGE) ((PAGE >> PTE_SHIFT) & ((1UL <<PDE_SHIFT)-1))
#define PAGE_TO_PTE(PAGE) (PAGE & ((1UL <<PTE_SHIFT)-1))

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

static inline void __list_add(struct list_head *_new,
			      struct list_head *prev,
			      struct list_head *next) {
	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	prev->next = _new;
}

static inline void list_add_tail(struct list_head *_new, struct list_head *head) {
	__list_add(_new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next) {
	next->prev = prev;
	prev->next = next;
}
static inline void list_del(struct list_head *entry) {
	__list_del(entry->prev, entry->next);
	entry->next = 0;
	entry->prev = 0;
}
static inline void list_init(struct list_head *entry) {
	entry->next = entry;
	entry->prev = entry;
}
#endif //PAGE_TABLE_H
