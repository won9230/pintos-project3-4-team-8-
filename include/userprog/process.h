#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define MAX_STR_LEN 128
#define MAX_NUM_STR 4


#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
struct thread* find_child(struct list *, tid_t);

int is_correct_pointer(const void *addr);

#endif /* userprog/process.h */
