/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
/* project 3 */
#include "lib/kernel/hash.h"
#include "threads/mmu.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();

#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();

	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
	ASSERT (VM_TYPE(type) != VM_UNINIT)
	bool succ = false;
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *new_page;
	/* Check wheter the upage is already occupied or not. */

	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling . You
		 * TODO: should modify the field after calling the uninit_new. */
		new_page = malloc(sizeof(struct page));

		bool (*page_initializer)(struct page *,enum vm_type,void *);
		//void *page_initializer;
		switch (VM_TYPE(type))
		{
			case VM_ANON:
				page_initializer = anon_initializer;
				break;
			case VM_FILE:
				page_initializer = file_backed_initializer;
				break;
		}

		uninit_new(new_page,upage,init,VM_UNINIT,aux,page_initializer);
		new_page->writable = writable;
		/* TODO: Insert the page into the spt. */
		if(spt_insert_page(spt,new_page) == NULL)
		{
			succ = true;
		}
		else
		{
			goto err;
		}
	}

	return succ;
err:
	free(new_page);
	return succ;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this func	tion.*/

	page = malloc(sizeof(struct page));
	page->va = pg_round_down(va);
	//page->va = va;

	struct hash_elem *elem = hash_find(&spt->spt_hash,&page->hash_elem);
	if(elem == NULL)
		return NULL;
	free(page);
	return hash_entry(elem,struct page,hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if(hash_insert(&spt->spt_hash,&page->hash_elem) == NULL)
	{
		succ = 0;
	}
	else
	{
		succ = 1;
	}

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->spt_hash,&page->hash_elem);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	struct hash_iterator i;	

    hash_first (&i, &thread_current()->spt.spt_hash);
    while (hash_next (&i)) {
        struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);

		if (page->frame == NULL) {
			continue;
		}

		if (pml4_is_accessed(thread_current()->pml4, page->va)) {
			pml4_set_accessed(thread_current()->pml4, page->va, 0);
			continue;
		}

		victim = page->frame;
		break;
    }
	if (victim == NULL) {
		struct hash_iterator i;
   		hash_first (&i, &thread_current()->spt.spt_hash);
		while (hash_next (&i)) {
			struct page *page = hash_entry(hash_cur(&i), struct page, hash_elem);

			if (page->frame == NULL) {
				continue;
			}

			if (pml4_is_accessed(thread_current()->pml4, page->va)) {
				pml4_set_accessed(thread_current()->pml4, page->va, 0);
				continue;
			}

			victim = page->frame;
			break;
    	}
	}

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {

	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);

	victim->page->frame = NULL;
	victim->page = NULL;

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	/* project 3 애매함*/
	// frame = vtop(malloc(sizeof(frame)));

	void *tmp = palloc_get_page(PAL_USER);
	// void *tmp = palloc_get_page(PAL_USER) + KERN_BASE;
	frame = malloc(sizeof(frame));
	if(tmp == NULL)
	{
		frame = vm_evict_frame();
	}
	else {
		frame->kva = tmp;
		frame->page = NULL;
	}

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	int i = 0;
	struct thread *curr = thread_current();
	while(true)
	{
		void *upage = pg_round_down(addr);
		size_t find_page = (uint64_t)upage + PGSIZE * i;
		if(spt_find_page(&curr->spt,find_page))
		{
			break;
		}
		if(vm_alloc_page(VM_ANON | VM_MARKER_0,find_page, true))
		{
			vm_claim_page(find_page);
		}
		i++;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {

}

/* Return true on success 깃북 소개에 있음 
	`user`
    - true: user에 의한 접근에 해당한다.
    - false: kernel에 의한 접근에 해당한다.*/
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {	
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);
	
	/* TODO: Validate the fault */
	if(addr == NULL)
		return false;
	if(is_kernel_vaddr(addr))
		return false;

	if(not_present)
	{
		void *rsp = f->rsp;
		if(!user)
		{
			rsp = thread_current()->rsp;
		}
		if(USER_STACK - (1 << 20) <= rsp - 8 && rsp - 8 <= addr && addr <= stack_bottom)
		{			
			//printf("fault page : %p\n",addr);
			vm_stack_growth(addr);
		}
		/* TODO: Your code goes here */

		page = spt_find_page(spt,addr);
		if(page == NULL)
		{
			return false;
		}
		if(write == 1 && page->writable == 0)
		{
			return false;
		}

		return vm_do_claim_page (page);
	}

	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	/* project 3 */
	page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL)
	{
		return false;
	}

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *curr = thread_current();	
	/* Set links */
	frame->page = page;
	page->frame = frame;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* project 3 */
	pml4_set_page(curr->pml4,page->va,frame->kva,page->writable);
	//printf("");

	return swap_in(page,frame->kva);
}
/* project 3 const void *buf_, size_t size*/
uint64_t hash_func(const struct hash_elem *e, void *aux)
{
	struct page *page_a = hash_entry(e,struct page,hash_elem);
	return hash_bytes(&page_a->va,sizeof page_a->va);
}

bool hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	return hash_entry(a, struct page, hash_elem)->va < hash_entry(b, struct page, hash_elem)->va;
}

void hash_destory_action(const struct hash_elem *e, void *aux)
{
	struct page *page = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page(page);
}
/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/* project 3 */
	hash_init(&spt->spt_hash,hash_func,hash_less,NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	if(dst == NULL || src == NULL)
	{
		return false;
	}
	struct hash_iterator i;
	hash_first(&i, &src->spt_hash);

	while(hash_next(&i))
	{
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		//bool writable = src_page->writable;
		// printf("1Type : %d\n",type);
		// printf("2Type : %d\n",VM_TYPE(src_page->operations->type));
		if(VM_TYPE(type) == VM_UNINIT)
		{
			vm_initializer *init = src_page->uninit.init;
			void *aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(VM_ANON, upage, src_page->writable, init, aux);
			continue;
		}
		else if(VM_TYPE(type) == VM_FILE)
		{
			struct lazy_load_struct *lazy_load_struct = malloc(sizeof(struct lazy_load_struct));
			lazy_load_struct->file = src_page->file.file;
			lazy_load_struct->offset = src_page->file.offset;
			lazy_load_struct->page_read_bytes = src_page->file.page_read_bytes;
			lazy_load_struct->page_zero_bytes = src_page->file.page_zero_bytes;
			if(!vm_alloc_page_with_initializer(VM_TYPE(type),upage,src_page->writable,NULL,lazy_load_struct))
			{
				return false;
			}
			struct page *file_page = spt_find_page(dst,upage);
			file_backed_initializer(file_page,type,NULL);
			file_page->frame = src_page->frame;
			pml4_set_page(thread_current()->pml4, file_page->va, src_page->frame->kva, src_page->writable);
			continue;
		}
		if(!vm_alloc_page_with_initializer(VM_TYPE(type), upage, src_page->writable, NULL, NULL))
		{
			return false;
		}
		if(!vm_claim_page(upage))
		{
			return false;
		}

		struct page *dst_page = spt_find_page(dst, upage);
		if(dst_page == NULL)
		{
			return false;
		}
		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%p\n",spt);
	hash_clear(&spt->spt_hash,hash_destory_action);
}