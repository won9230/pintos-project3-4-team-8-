#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "include/threads/vaddr.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"



struct lock filesys_lock; 
void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

/**
 * initailize syscall
*/
void syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);
	lock_init(&filesys_lock);
	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/**
 * The main system call interface
 * @param f
*/
void syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

	switch (f -> R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_WRITE:
			f -> R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_FORK:
			f -> R.rax = fork(f->R.rdi, f);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		default:
			break;
	}

}

/* 프로세스 관련 시스템 콜 */

/**
 * halt 
*/
void halt(void) {
	power_off();
}

/**
 * exit
 * @param status
*/
void exit(int status) {
	struct thread *curr = thread_current();
	// 현재 사용자 프로그램을 종료하고 상태를 커널에 반환한다.
	// 민약 해당 프로세스의 부모 프로세스가 존재하고 대기 중이라면 종료 상태값이 부모 프로세스에게 반환된다.
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

/**
 * fork
 * @param thread_name
*/
pid_t fork (const char *thread_name, struct intr_frame* if_ ) {

	return process_fork(thread_name, if_);
}

/**
 * exec
 * @param file
*/
int exec (const char *file) {
	if(!is_correct_pointer(file))
		exit(-1);
	char * fn_copy = palloc_get_page(PAL_ZERO);
	if(fn_copy == NULL)
		exit(-1);
	strlcpy(fn_copy, file, PGSIZE);
	if(process_exec(fn_copy)== -1){
		exit(-1);
	}
}

/**
 * wait
 * @param pid_t
*/
int wait (pid_t pid) {
	return process_wait(pid);
}

/* 파일 관련 시스템 콜 */

/**
 * create
 * @param file
 * @param initial_size
*/
bool create(const char *file, unsigned initial_size) {
	if(!is_correct_pointer(file)) {
		exit(-1);
	}

	// 2. Use bool filesys_create(const char *name, off_t initial_size).
	// 3. Return true if it is succeeded or false if it is not.
	return filesys_create(file, initial_size);
}

/**
 * remove
 * @param file
*/
bool remove (const char *file) {
	// Use bool filesys_remove(const char *name).
	if(!is_correct_pointer(file)) {
		exit(-1);
	}

	// Return true if it is succeeded or false if it is not.
	return filesys_remove(file);
}

/**
 * open
 * @param file
*/
int open (const char *file) {
	if(!is_correct_pointer(file)) {
		exit(-1);
	}

	struct thread *curr = thread_current();
	struct file *now_file = filesys_open(file);
	struct file **fdt = curr->fdt;

	int fd = -1;

	if(now_file == NULL) {
		return -1;
	}

	for (int i = 2; i < 128; i++) {
		if(fdt[i] == 0) {
			fdt[i] = now_file;
			fd = i;
			curr->next_fd = i + 1;
			break;
		}
	}

	if(fd == -1) {
		file_close(now_file);
	}

	return fd;
}

/**
 * filesize
 * @param fd
*/
int filesize (int fd) {
	if (fd < 0 || fd >= 128) {
		return NULL;
	}

	struct thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	struct file *now_file = fdt[fd];

	if(now_file == 0) {
		return -1;
	}

	return file_length(now_file);
};

/**
 * read
 * @param fd
 * @param buffer
 * @param length
*/
int read (int fd, void *buffer, unsigned length) {
	
	if(!is_correct_pointer(buffer)) {
		exit(-1);
	}

	if (fd < 0 || fd >=128) {
		return -1;
	}

	struct thread *curr = thread_current();
	struct file *now_file = curr->fdt[fd];
	char *ptr = buffer;
	int size = 0;

	if(now_file == 0) {
		return -1;
	}

	if (fd == 0) {
		// STANDARD INPUT
		char key;

		for (int size = 0; size < length; size++)
		{
			key = input_getc();
			*ptr++ = key;

			if(key == '\0') {
				break;
			}
		}
	}else if (fd == 1) {
		// STANDARD OUTPUT
		return -1;
	}else {
		lock_acquire(&filesys_lock);
		size = file_read(now_file, buffer, length);
		lock_release(&filesys_lock);
	}

	return size;
}

/**
 * write
 * @param fd
 * @param buffer
 * @param size
*/
int write (int fd, const void *buffer, unsigned size) {
	if(!is_correct_pointer(buffer)) {
		exit(-1);
	}

	if(fd <= 0 || fd >= 128) {
		exit(-1);
	}

	int written_size = 0;

	// 만약 fd = 1 이면 putbuf() 사용해서 출력
	if(fd == 1) {
		putbuf(buffer, size);
	}else {
		struct thread *curr = thread_current();
		struct file *now_file = curr->fdt[fd];

		written_size = file_write(now_file, buffer, size);
	}

	return written_size;
};

/**
 * seek
 * @param fd
 * @param position
*/
void seek (int fd, unsigned position) {
	if (fd < 0 || fd >= 128) {
		exit(-1);
	}

	struct thread *curr = thread_current();
	struct file *now_file = curr->fdt[fd];

	file_seek(now_file, position);
};

/**
 * tell
 * @param fd
*/
unsigned tell (int fd) {
	if (fd < 0 || fd >= 128) {
		exit(-1);
	}

	struct thread *curr = thread_current();
	struct file *now_file = curr->fdt[fd];

	return file_tell(now_file);
};

/**
 * close
 * @param fd
*/
void close (int fd) {
	if (fd < 0 || fd >= 128) {
		exit(-1);
	}

	file_close(fd);
};