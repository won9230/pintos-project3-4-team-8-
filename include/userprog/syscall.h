#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

void syscall_init (void);

void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
int write (int fd, const void *buffer, unsigned length);


#endif /* userprog/syscall.h */
