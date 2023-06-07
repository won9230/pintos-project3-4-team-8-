#include "include/lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"

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

	// USER MEMORY ACCESS
	// 시스템 호출의 인자로 제공된 

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
		default:
			break;
	}
}

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

	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
} 

/**
 * write
 * @param fd
 * @param buffer
 * @param size
*/
int write (int fd, const void *buffer, unsigned size) {
	// 만약 fd = 1 이면 putbuf() 사용해서 출력
	if(fd == 1) {
		putbuf(buffer, size);

		return size;
	}
};