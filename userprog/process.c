#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);


int is_correct_pointer(const void *addr) {
	struct thread *curr = thread_current();

	if(is_kernel_vaddr(addr) || addr == NULL) {
		return 0;
	}

	// if(pml4_get_page(curr->pml4, addr) == NULL) {
	// 	return 0;
	// }

	return 1;
}

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();

	if(current != current->parent){
		list_push_back(&current -> parent -> child_list, &current->p_elem);
	}
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	char** save_ptr;
	struct thread *curr = thread_current();

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);

	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	return thread_create (name, PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();    // child thread
	struct thread *parent = (struct thread *) aux; // parent thread
	void *parent_page;
	void *newpage;
	bool writable;

	if(!is_correct_pointer(va)){
		return true;
	}

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (pte == base_pml4) {
		return false;
	}

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_ZERO);
	if(newpage == NULL) {
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */	
	memcpy(newpage, parent_page, PGSIZE);

	if(is_writable(pte)) {
		writable = true;
	}else {
		writable = false;
	}

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
        palloc_free_page(newpage);
		return false;
	}

	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux; // parent thread
	struct thread *current = thread_current();     // child thread

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	parent_if = &parent->tf;

	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	// current->parent = parent;
	// list_push_back(&parent->child_list, &current->p_elem);
	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	
	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */

int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *curr = thread_current(); // 현재 스레드
	struct thread *child_thread = find_child(&curr->child_list, child_tid);			// 자식 스레드가 존재한다면? 자식 스레드 
	
	// 만약 자식 스레드가 존재한다면? 끝날 때까지 기다린다.
	if (child_thread != NULL){
		sema_down(&child_thread->p_sema);
		int exit_status = curr->exit_status;
		list_remove(&child_thread->p_elem); // 자식 스레드를 자식 스레드 리스트에서 제거
		sema_up(&child_thread->e_sema);
		return exit_status;
	}

	// wait 함수가 실패할 경우에는 -1을 반환한다.
	// 아래 두 가지 경우일 때에도 -1을 반환한다.
	// 1. child_tid의 스레드가 현재 스레드의 직접적인 자식 스레드가 아닌 경우.
	// 2. child_tid의 wait()이 이미 호출된 경우.
	return -1;
}

struct thread* find_child(struct list *c_list, tid_t child_tid) {
	for (struct list_elem* e = list_begin (c_list); e != list_end (c_list); e = list_next (e)) {
		struct thread *child_thread =list_entry(e, struct thread, p_elem);
		
		if (child_thread->tid== child_tid){
			return child_thread;
		}
 	}

	return NULL;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	
	process_cleanup ();
	sema_up(&curr->p_sema);
	sema_down(&curr->e_sema);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* 
		현재 프로세스의 페이지 디렉토리를 제거하고, 커널 전용 페이지 디렉토리로 다시 전환한다.
		(운영 체제는 가상 메모리 관리를 위해 프로세스마다 별도의 페이지 디렉토리를 사용한다. 
		페이지 디렉토리는 가상 주소 공간과 실제 물리 메모리를 매핑하는 역할을 한다.)
	*/
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* 
			아래 작업을 수행할 때 순서를 지켜주는 것은 매우 중요하다.
			
			1. curr -> pagedir 를 NULL로 설정한다. : curr는 현재 프로세스를 가리키는 포인터.
			즉 현재 프로세스의 페이지 디렉터리를 NULL로 설정해서 타이머 인터럽트가 프로세스 페이지 디렉토리로 다시 전환되는 것을 방지하기 위함.
			타이머 인터럽트가 발생하더라도 현재 종료되는 프로세스의 페이지 디렉토리로 다시 돌아가지 않도록 하는 것.
			
			2. 활성화된 페이지 디렉토리를 기본 페이지 디렉토리로 변경한다.
			이렇게 하면 현재 활성화된 페이지 디렉토리가 이미 해제되거나 초기화되었다고 가정하는 문제를 방지할 수 있다.

			3. 마지막으로, 종료되는 프로세스의 페이지 디렉토리를 파괴한다. 이는 해당 프로세스의 페이지 디렉토리와 관련된 자원을 해제하고 정리하는 작업.
		*/
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current (); // 현재 실행 중인 스레드를 가지고 온다.
	
	// 실행 파일의 정보를 저장하기 위한 변수 및 파일 포인터 초기화
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	// 최대 128바이트까지 인자 받을 수 있음.
	char *argv[MAX_STR_LEN];
	char **save_ptr;
	uint64_t argc = 0;

	// 임시 변수에 복사하여 원래의 문자열을 보존 -> 혹시 몰라서
	char temp[MAX_STR_LEN];
	strlcpy(temp, file_name, sizeof(temp));

	char *token = strtok_r(temp, " ", &save_ptr);

	while (token != NULL) {
		argv[argc] = token;
		// strlcpy(argv[argc], token, MAX_STR_LEN);
		argc++;

		token = strtok_r(NULL, " ", &save_ptr);
	}

	// 현재 실행 중인 스레드의 페이지 디렉터리 생성 & 초기화
	t->pml4 = pml4_create (); 
		
	// thread 구조체의 pml4 필드에 페이지 디렉터리의 주소가 저장된다.
	// 오류 발생 시 함수 종료.
	if (t->pml4 == NULL) 
		goto done;

	// 현재 실행 중인 스레드의 페이지 디렉터리를 활성화 한다.
	// 활성화하면 해당 프로세스의 가상 주소 공간에 접근할 수 있게 된다.
	process_activate (thread_current ()); 

	// 새롭게 실행 할 파일을 연다 (인자로 전달된 file_name으로..) 
	file = filesys_open (argv[0]);
	
	// 파일이 존재하지 않는다면 실패 메세지를 출력하고 함수를 종료한다.
	if (file == NULL) {
		goto done;
	}

	// 새롭게 실행 할 파일의 헤더를 읽고 유효성을 검증한다.
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7) // ELF 파일의 식별자를 검사하여 ELF 파일인지 확인한다.
			|| ehdr.e_type != 2                          // ELF 파일의 형식 필드를 검사한다. 2는 실행 가능한 파일을 나타내는 값
			|| ehdr.e_machine != 0x3E                    // ELF 파일의 아키텍처 필드를 검사한다. 0x3e는 amd 아키텍처를 뜻한다.
			|| ehdr.e_version != 1						 // ELF 파일의 버전 필드를 검사한다.
			|| ehdr.e_phentsize != sizeof (struct Phdr)  // ELF 파일 프로그램 헤더의 크기 필드를 검사한다.
			|| ehdr.e_phnum > 1024)                      // ELF 파일 프로그램 헤더의 개수 필드를 검사한다.
	{
		// 위 조건에 맞는 ELF 파일이 아닌 경우에 오류 출력 후 함수 종료.
		goto done;
	}

	// 실행 할 ELF 파일의 프로그램 헤더를 읽어 세그먼트를 로드한다. 
	// (프로그램 헤더는 ELF 파일 내에 여러 세그먼트에 대한 정보를 담고 있다.)

	// 프로그램 헤더 테이블 시작 위치를 변수 file_ofs에 할당
	file_ofs = ehdr.e_phoff;

	// 프로그램 헤더 테이블의 개수(e_phnum)만큼 프로그램 헤더를 읽고 처리한다.
	for (i = 0; i < ehdr.e_phnum; i++) {
		// 프로그램 헤더를 저장하기 위한 구조체
		struct Phdr phdr;

		// 현재 프로그램 헤더의 오프셋 값이 파일의 범위를 벗어났거나 음수일 경우 오류로 간주하고 함수 종료.
		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;

		// 파일을 읽을 위치를 file_ofs으로 이동 시킨다.
		// file_read 호출에서 file_ofs 위치부터 읽을 수 있음.
		file_seek (file, file_ofs);

		// 파일에서 phdr에 sizeof phdr 만큼 데이터를 읽어 왔을 때, 크기가 sizeof phdr와 다르다면 오류로 간주.
		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;

		// 다음 프로그램 헤더를 읽기 위해서 file_ofs 값을 증가시긴다.
		file_ofs += sizeof phdr;

		// 현재 프로그램 헤더의 세그먼트 타입을 확인하고, 해당 세그먼트의 처리를 수행한다.
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				// PT_NULL, PT_NOTE, PT_PHDR, PT_STACK일 경우 무시하고 다음 프로그램 헤더로 이동.
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				// PT_DYNAMIC, PT_INTERP, PT_SHLIB 일 경우 처리를 중단하고 done
				goto done;
			case PT_LOAD:
				// PT_LOAD일 경우 해당 세그먼트는 로드해야 하는 유효한 세그먼트이다.
				// validate_segment를 사용해서 세그먼트를 검증한 후에 해당 세그먼트를 메모리에 로드한다.
				// 로드 할 때 읽어야할 바이트 수와 초기화되지 않은 영역의 크기를 계산해서 전달한다.
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}

					// 세그먼트가 성공적으로 로드되지 않으면 done으로 분기처리 하여 처리를 종료한다.
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				
				else
					goto done;
				break;
		}
	}

	// 스택을 설정하는 함수인 setup_stack을 호출해서 스택을 초기화한다. 
	// 스택 설정에 실패하면 done으로 분기처리 후 처리 종료
	if (!setup_stack (if_))
		goto done;

	// ELF 파일의 진입점 주소를 저장한다. 프로그램 실행은 이 주소부터 시작된다.
	if_->rip = ehdr.e_entry;

	/* arguments passing */

	// argv 인자들을 스택에 push
	for(int i = argc - 1; i >= 0; i--) {
		size_t arg_len = strlen(argv[i]) + 1;    // 널 문자 포한한 인자의 길이 계산.
		if_->rsp -= arg_len;                     // 스택 포인터를 인자의 길이만큼 이동하여 공간을 확보.
		memcpy(if_->rsp, argv[i], arg_len);      // 인자를 스택에 복사한다.
	
		argv[i] = (char *)if_->rsp;
	}

	// 패딩 값 설정.
	// x64 시스템  -> double word align
	// 8의 배수로 내림해준다.
	if(if_->rsp % 8 != 0) {
		if_->rsp = (if_->rsp / 8) * 8;
	}

	// 널 포인터를 센티넬 값으로 push 
	// 즉 argv[argc] = NULL 을 센티넬 값으로 push
	if_->rsp -= 8;
	memset(if_->rsp, 0, 8);

	// 주소 포인터들을 스택에 push
	for (int i = argc - 1; i >= 0; i--) {
		if_->rsp -= 8;  				// 주소 포인터 크기만큼 스택 포인터 이동
		memcpy(if_->rsp, &argv[i], 8);  // 주소 포인터를 스택에 저장
	}

	// 함수 호출을 위해 레지스터 설정
	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp;

	// fake return address
	if_->rsp -= 8;
	memset(if_->rsp, 0, 8);

	// 성공적으로 ELF 파일이 로드되었으므로 success 변수를 true로 설정한다.
	success = true;

done:
	// goto done 문이 실행되었을 때의 처리 목록
	// 오류가 발생했을 때 OR 처리가 완료되었을 때 실행된다.

	// 파일을 닫고, 성공 여부를 반환한다.
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
