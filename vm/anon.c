/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
/* project 3 */
#include "threads/malloc.h"
#include "threads/mmu.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
bool *swap_arr;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	//lock_init(&swap_table_lock);
	int swap_arr_len = disk_size(swap_disk) / 8;
	swap_arr = malloc(swap_arr_len);

	for (int i = 0; i < swap_arr_len; i++) {
		swap_arr[i] = false;
	}

}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
	anon_page->sector_numder = -1;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	int start_sector_no = anon_page->sector_numder;
	anon_page->sector_numder = -1;

	if(start_sector_no == -1)
		start_sector_no = 0;

	int j = 0;
	swap_arr[start_sector_no / 8] = false;

	for (int i = start_sector_no; i < start_sector_no + 8; i++) {
		disk_read(swap_disk, i, kva + j * DISK_SECTOR_SIZE);
		j++;
	}

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;	

	int arr_len = disk_size(swap_disk) / 8;
	int start_sec_no = 0;

	/* page가 들어갈 수 있는 sector 위치 찾기 */
	for(int i = 0; i < arr_len; i++) {
		if (swap_arr[i] == false) {
			swap_arr[i] = true;
			start_sec_no = i * 8;
			break;
		}
	}

	/* 해당 sector 위치에 page를 8개로 쪼개 넣기 */
	int j = 0;
	page->anon.sector_numder = start_sec_no;	// anon_page에 start_sec_no 저장
	for (int i = start_sec_no; i < start_sec_no + 8; i++) {
		disk_write(swap_disk, i, page->frame->kva + j * DISK_SECTOR_SIZE);
		j++;
	}

	pml4_clear_page(thread_current()->pml4, page->va);
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
