#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>
#include "threads/thread.h"


/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

void syscall_init (void);


int is_correct_pointer(const void *addr);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t fork (const char *, struct intr_frame* );
int exec (const char *file);
int wait (pid_t id);
int write (int fd, const void *buffer, unsigned length);


#endif /* userprog/syscall.h */
