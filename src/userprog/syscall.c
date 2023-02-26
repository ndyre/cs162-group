#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/kernel/console.h"


static void syscall_handler(struct intr_frame*);

// System calls
void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_file_size(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, void *buffer, unsigned size);
void sys_close(int fd);
int sys_practice(int i);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);

// User pointer validation
void check_user_stack_addresses(uint32_t* uaddr, size_t num_bytes);
void check_arg_pointers(const char *arg_pointer);

struct file* get_file(int fd);


void syscall_init(void) { 
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
  lock_init(&fileop_lock);
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  // printf("System call number: %d\n", args[0]);

  check_user_stack_addresses(args, 4);
  if (args[0] < 4)
  {
    switch(args[0])
    {
      case SYS_HALT:
        //TODO
        break;
      case SYS_EXIT:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        f->eax = args[1];
        sys_exit(args[1]);
        break;
      case SYS_EXEC:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        check_arg_pointers((const char*)args[1]);
        f->eax = sys_exec(args[1]);
        break;
      case SYS_WAIT:
        //TODO
        break;
    }
  }
  else
  {
    lock_acquire(&fileop_lock);
    switch(args[0])
    {
      case SYS_CREATE:
        //TODO
        check_user_stack_addresses(args + 1, 8);
        check_arg_pointers((const char*)args[1]);
        f->eax = sys_create((const char*) args[1], args[2]);
        break;
      case SYS_REMOVE:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        check_arg_pointers((const char*)args[1]);
        f->eax = sys_remove((const char*) args[1]);
        break; 
      case SYS_OPEN:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        check_arg_pointers((const char*)args[1]);
        f->eax = sys_open((const char*)args[1]);
        break;
      case SYS_FILESIZE:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        f->eax = sys_file_size(args[1]);
        break;
      case SYS_READ:
        //TODO
        check_user_stack_addresses(args + 1, 12);
        check_arg_pointers(args[2]);
        f->eax = sys_read(args[1], args[2], args[3]);
        break;
      case SYS_WRITE:
        //TODO
        check_user_stack_addresses(args + 1, 12);
        check_arg_pointers(args[2]);
        f->eax = sys_write(args[1], args[2], args[3]);
        break;
      case SYS_SEEK:
        //TODO
        check_user_stack_addresses(args + 1, 8);
        sys_seek(args[1], args[2]);
        break;
      case SYS_TELL:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        f->eax = sys_tell(args[1]);
        break;
      case SYS_CLOSE:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        sys_close(args[1]);
        break;
      case SYS_PRACTICE:
        //TODO
        check_user_stack_addresses(args + 1, 4);
        f->eax = sys_practice(args[1]);
        break; 
    }
    lock_release(&fileop_lock);
  }
}

void sys_halt() {
  // TODO
}

void sys_exit(int status) {
  // TODO
  struct thread* t = thread_current();
  t->pcb->status = status;
  process_exit();
}

pid_t sys_exec(const char *cmd_line) {
  pid_t pid = process_execute(cmd_line);
  return pid;
}

int sys_wait(pid_t pid) {
  // TODO
}

bool sys_create(const char *file, unsigned initial_size) {
  // TODO
  return filesys_create(file, initial_size);
}

bool sys_remove(const char *file) {
  // TODO
  return filesys_remove(file);
}

int sys_open(const char *file) {
  // TODO
  struct fdt_entry* fdt_entry = malloc(sizeof(struct fdt_entry));
  fdt_entry->file = filesys_open(file);
  
  if (fdt_entry->file == NULL) {
    return -1;
  }

  struct thread* t = thread_current();
  fdt_entry->fd = t->pcb->max_fd++;
  list_push_back(&t->pcb->fdt, &fdt_entry->elem);

  return fdt_entry->fd;
}

int sys_file_size(int fd) {
  // TODO
  struct file* file = get_file(fd);
  if (file == NULL) {
    return -1;
  }

  return file_length(file);
}

int sys_read(int fd, void *buffer, unsigned size) {
  // TODO
  if (fd == 0)
  {
    char* input[size + 1];
    for (int i = 0; i < size; i++) {
      input[i] = input_getc();
    }
    input[size] = '\0';
    memcpy(buffer, (void*)input, size + 1);
    return size;
  }

  struct file* file = get_file(fd);
  if (file == NULL) {
    return -1;
  }

  return file_read(file, buffer, size);
}

int sys_write(int fd, void *buffer, unsigned size) {
  // TODO
  if (fd == 1)
  {
    putbuf(buffer, size);

    // Not sure what to return when writing to the console
    return size;
  }

  struct file* file = get_file(fd);
  if (file == NULL) {
    return -1;
  }

  return file_write(file, buffer, size);
}

void sys_seek(int fd, unsigned position) {
  // TODO
  struct file* file = get_file(fd);
  if (file == NULL) {
    return;
  }

  file_seek(file, position);
}

unsigned sys_tell(int fd) {
  struct file* file = get_file(fd);
  if (file == NULL) {
    return  -1;
  }

  return file_tell(file);
}

void sys_close(int fd) {
  struct file* file = get_file(fd);
  if (file == NULL) {
    return;
  }
  file_close(file);

  remove_file(fd);
}

int sys_practice(int i) {
  return ++i;
}

void check_arg_pointers(const char *arg_pointer) {
  char* arg_pointer_cpy = arg_pointer;
  if (arg_pointer_cpy == NULL) {
    sys_exit(-1);
  }
  
  while(true) {
    if (!is_user_vaddr((uint32_t* ) arg_pointer_cpy)) {
      sys_exit(-1);
    }
    else if (pagedir_get_page(thread_current()->pcb->pagedir, (const void*) arg_pointer_cpy) == NULL) {
      sys_exit(-1);
    }
    if (*arg_pointer_cpy == NULL) {
      break;
    }
    arg_pointer_cpy++;
  }
}


void check_user_stack_addresses(uint32_t* uaddr, size_t num_bytes) {
  // TODO
  if (uaddr == NULL) {
    sys_exit(-1);
  }
  // Cast to char* so ++ operator increments ptr by one byte
  char* uaddr_cpy = (char*) uaddr;
  for (size_t i = 0; i < num_bytes; i++) {
    if (!is_user_vaddr((uint32_t* )uaddr_cpy)) {
      sys_exit(-1);
    }
    else if (pagedir_get_page(thread_current()->pcb->pagedir, (const void*) uaddr_cpy) == NULL) {
      sys_exit(-1);
    }
    uaddr_cpy++;
  }
}


struct file* get_file(int fd) {
  if (fd == 0 || fd == 1) {
    return NULL;
  }
  
  struct process* cur_pcb = thread_current()->pcb;
  struct list_elem* e;
  for (e = list_begin(&cur_pcb->fdt); e != list_end(&cur_pcb->fdt); e = list_next(e)) {
    struct fdt_entry* fdt_entry = list_entry(e, struct fdt_entry, elem);
    if (fdt_entry->fd == fd) {
      return fdt_entry->file;
    }
  }
  return NULL;
}

// Removes and frees entry from fdt
void remove_file(int fd) {
  struct process* cur_pcb = thread_current()->pcb;
  struct list_elem* e;

  while (!list_empty (&cur_pcb->fdt))
  {
    struct list_elem *e = list_pop_front(&cur_pcb->fdt);
    struct fdt_entry* fdt_entry = list_entry(e, struct fdt_entry, elem);
    if(fdt_entry->fd == fd) {
      list_remove(&fdt_entry->elem);
      free(fdt_entry);
    }
  }
}