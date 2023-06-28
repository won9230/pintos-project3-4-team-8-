/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

/* project 3 */
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include <round.h>
#include <string.h>
#include "userprog/process.h"
#include "threads/mmu.h"
#include "lib/kernel/hash.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
	
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;

	struct lazy_load_struct *lazy_load_struct = (struct lazy_load_struct *)page->uninit.aux;
	file_page->file = lazy_load_struct->file;
	file_page->offset = lazy_load_struct->offset;
	file_page->page_read_bytes = lazy_load_struct->page_read_bytes;
	file_page->page_zero_bytes = lazy_load_struct->page_zero_bytes;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;

	file_read_at(file_page->file, kva, file_page->page_read_bytes, file_page->offset);
	memset(kva + file_page->page_read_bytes, 0, file_page->page_zero_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;

	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
		file_write_at(file_page->file, page->frame->kva, file_page->page_read_bytes, file_page->offset);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}

	pml4_clear_page(thread_current()->pml4, page->va);
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct thread *curr = thread_current();

	if(pml4_is_dirty(curr->pml4,page->va))
	{
		file_write_at(file_page->file,page->va,file_page->page_read_bytes,file_page->offset);
		pml4_set_dirty(curr->pml4,page->va,0);
	}
	pml4_clear_page(curr->pml4, page->va);

	//hash_delete(&curr->spt.spt_hash, &page->hash_elem);
	// if(file_page->file_type & VM_MARKER_1)
	// {
	// 	free(file_page->lazy_load_struct->file);
	// 	free(page->file.lazy_load_struct);
	// }
}


/* Do the mmap project 3*/
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	struct file *f = file_reopen(file);
	void *now_addr = addr;
	size_t num_pages = DIV_ROUND_UP(length, PGSIZE);
	for(size_t i = 0; i < num_pages; i++)
	{
		size_t page_read_byte = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_byte = PGSIZE - page_read_byte;
		struct lazy_load_struct *lazy_load_struct = malloc(sizeof(struct lazy_load_struct));
		
		lazy_load_struct->file = malloc(sizeof(struct file));
		memcpy(lazy_load_struct->file, f, sizeof(struct file));
		lazy_load_struct->page_read_bytes = page_read_byte;
		lazy_load_struct->page_zero_bytes = page_zero_byte;
		lazy_load_struct->offset = offset;
	
		file_seek(lazy_load_struct->file, offset);

		if(!vm_alloc_page_with_initializer(i == num_pages - 1 ? (VM_FILE | VM_MARKER_0) : VM_FILE, now_addr, writable, lazy_load_segment, lazy_load_struct))
		{
			return NULL;
		}
		spt_find_page(&thread_current()->spt,now_addr)->mapped_page_count = num_pages;
		length -= page_read_byte;
		offset += page_read_byte;
		now_addr += PGSIZE;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *delet_page = spt_find_page(spt, addr);
	int count = delet_page->mapped_page_count;
	for(int i =0; i < count; i++)
	{
		if(delet_page)
		{
			destroy(delet_page);
		}
		addr += PGSIZE;
		delet_page = spt_find_page(spt,addr);
	}
}

