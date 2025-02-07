#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void close_all_files(struct thread*);

//bool setup_stack (void **esp);
//bool validate_segment (const struct Elf32_Phdr *, struct file *);
//bool load_segment (struct file *, off_t, uint8_t *, uint32_t, uint32_t, bool);

#endif /* userprog/process.h */
