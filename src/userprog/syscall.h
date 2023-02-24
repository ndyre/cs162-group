#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

// struct open_file {
//   struct list_elem elem;
//   struct file* f;
//   int fd;
// };

struct lock fileop_lock;

#endif /* userprog/syscall.h */
