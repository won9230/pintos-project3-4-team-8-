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


void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
pid_t fork (const char *, struct intr_frame* );
int exec (const char *file);
int wait (pid_t id);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

#endif /* userprog/syscall.h */
