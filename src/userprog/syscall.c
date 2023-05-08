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
#include "lib/float.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#define CHECK_STACK_PTRS0(args) check_user_stack_addresses(args, 4);
#define CHECK_STACK_PTRS1(args) check_user_stack_addresses(args + 1, 4)
#define CHECK_STACK_PTRS2(args) check_user_stack_addresses(args + 1, 8)
#define CHECK_STACK_PTRS3(args) check_user_stack_addresses(args + 1, 12)

#define CHECK_ARGS_PTR1(args) check_arg_pointers((const char*)args[1])
#define CHECK_ARGS_PTR2(args) check_arg_pointers((const char*)args[2]);

static void syscall_handler(struct intr_frame*);

/* SYSTEM CALLS */
void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char* cmd_line);
int sys_wait(pid_t pid);
int sys_compute_e(int n);
bool sys_create(const char* file, unsigned initial_size);
bool sys_remove(const char* file);
int sys_open(const char* file);
int sys_file_size(int fd);
int sys_read(int fd, void* buffer, unsigned size);
int sys_write(int fd, void* buffer, unsigned size);
void sys_close(int fd);
int sys_practice(int i);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
bool sys_chdir(const char* name);
bool sys_mkdir(const char* name);
bool sys_readdir(int fd, char* name); 
bool sys_isdir(int fd);
int sys_inumber(int fd);
int sys_num_hits(void);
void sys_reset_cache(void);

/* HELPER FUNCTIONS */

// User pointer validation
void check_user_stack_addresses(uint32_t* uaddr, size_t num_bytes);
void check_arg_pointers(const char* arg_pointer);

// Removes file from fdt and frees
void remove_fdt_entry(int fd);

// Get file from fdt
struct fdt_entry* get_fdt_entry(int fd);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  // printf("System call number: %d\n", args[0]);

  CHECK_STACK_PTRS0(args);
  if (args[0] < 4) {
    switch (args[0]) {
      case SYS_HALT:
        sys_halt();
        break;
      case SYS_EXIT:
        CHECK_STACK_PTRS1(args);
        f->eax = args[1];
        sys_exit(args[1]);
        break;
      case SYS_EXEC:
        CHECK_STACK_PTRS1(args);
        CHECK_ARGS_PTR1(args);
        f->eax = sys_exec((const char*)args[1]);
        break;
      case SYS_WAIT: 
        CHECK_STACK_PTRS1(args);
        f->eax = sys_wait(args[1]);
        break;
    }
  } else if (args[0] >= 4 && args[0] < 13) {
    switch (args[0]) {
      case SYS_CREATE:
        CHECK_STACK_PTRS2(args);
        CHECK_ARGS_PTR1(args);
        f->eax = sys_create((const char*)args[1], args[2]);
        break;
      case SYS_REMOVE:
        CHECK_STACK_PTRS1(args);
        CHECK_ARGS_PTR1(args);
        f->eax = sys_remove((const char*)args[1]);
        break;
      case SYS_OPEN:
        CHECK_STACK_PTRS1(args);
        CHECK_ARGS_PTR1(args);
        f->eax = sys_open((const char*)args[1]);
        break;
      case SYS_FILESIZE:
        CHECK_STACK_PTRS1(args);
        f->eax = sys_file_size(args[1]);
        break;
      case SYS_READ:
        CHECK_STACK_PTRS3(args);
        CHECK_ARGS_PTR2(args);
        f->eax = sys_read(args[1], (void*)args[2], args[3]);
        break;
      case SYS_WRITE:
        CHECK_STACK_PTRS3(args);
        CHECK_ARGS_PTR2(args);
        f->eax = sys_write(args[1], (void*)args[2], args[3]);
        break;
      case SYS_SEEK:
        CHECK_STACK_PTRS2(args);
        sys_seek(args[1], args[2]);
        break;
      case SYS_TELL:
        CHECK_STACK_PTRS1(args);
        f->eax = sys_tell(args[1]);
        break;
      case SYS_CLOSE:
        CHECK_STACK_PTRS1(args);
        sys_close(args[1]);
        break;
    }
  } else {
    switch (args[0]) {
      case SYS_PRACTICE:
        CHECK_STACK_PTRS1(args);
        f->eax = sys_practice(args[1]);
        break;
      case SYS_COMPUTE_E:
        CHECK_STACK_PTRS1(args);
        f->eax = sys_compute_e(args[1]);
        break;
      case SYS_CHDIR:
        CHECK_STACK_PTRS1(args);
        CHECK_ARGS_PTR1(args);
        f->eax = sys_chdir((const char*) args[1]);
        break;
      case SYS_MKDIR:
        CHECK_STACK_PTRS1(args);
        CHECK_ARGS_PTR1(args);
        f->eax = sys_mkdir((const char*) args[1]);
        break;
      case SYS_READDIR:
        CHECK_STACK_PTRS2(args);
        CHECK_ARGS_PTR2(args);
        f->eax = sys_readdir(args[1], args[2]);
        break;
      case SYS_ISDIR:
        CHECK_STACK_PTRS1(args);
        f->eax = sys_isdir(args[1]);
        break;
      case SYS_INUMBER:
        CHECK_STACK_PTRS1(args);
        f->eax = sys_inumber(args[1]);
        break;
      case SYS_RESET_CACHE:
        sys_reset_cache();
        break;
      case SYS_NUM_HITS:
        f->eax = sys_num_hits();
        break;
    }
  }
}

int sys_num_hits(void) {
  return get_cache_hits();
} 
void sys_reset_cache(void) {
  buffer_cache_flush();
}

bool sys_mkdir(const char* name) {
  if (strlen(name) == 0) {return false;}
  return filesys_mkdir(name);
}

bool sys_chdir(const char* name) {
  return filesys_chdir(name);
}

bool sys_readdir(int fd, char* name) {
  bool success = false;
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry != NULL && fdt_entry->is_dir) {
    success = dir_readdir(fdt_entry->dir, name);
  }
  return success;
}

bool sys_isdir(int fd) {
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL) {
    return false;
  }
  return fdt_entry->is_dir;
}

int sys_inumber(int fd) {
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL) {
    return -1;
  }

  struct inode* inode;
  if (fdt_entry->is_dir) {
    inode = dir_get_inode(fdt_entry->dir);
  } else {
    inode = file_get_inode(fdt_entry->file);
  }
  return inode_get_inumber(inode);
}

void sys_halt() {
  shutdown_power_off();
}

/* Current process is done.  Set it's exit status in shared data.  
   Process_exit will free pcb, and free shared_data if ref_cnt == 0
*/
void sys_exit(int status) {
  struct thread* t = thread_current();
  struct shared_data_struct* shared_data = t->pcb->shared_data;
  lock_acquire(&(shared_data->shared_data_lock));
  shared_data->shared_data_status = status;
  lock_release(&(shared_data->shared_data_lock));
  process_exit();
}

pid_t sys_exec(const char* cmd_line) {
  pid_t pid = process_execute(cmd_line);
  return pid;
}

int sys_wait(pid_t pid) {
  int exit_status = process_wait(pid);
  return exit_status;
}

int sys_compute_e(int n) { return sys_sum_to_e(n); }

bool sys_create(const char* file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

bool sys_remove(const char* file) {
  return filesys_remove(file);
}

int sys_open(const char* file) {
  struct fdt_entry* fdt_entry = malloc(sizeof(struct fdt_entry));
  fdt_entry->file = NULL;
  fdt_entry->dir = NULL;
  struct file* f = filesys_open(file);
  if (f == NULL) {
    return -1;
  }
  struct inode* inode = file_get_inode(f);
  if (get_is_dir(inode)) {
    fdt_entry->is_dir = true;
    fdt_entry->dir = f;
  }
  else {
    fdt_entry->file = f;
    fdt_entry->is_dir = false;
  }
  if (fdt_entry->file == NULL && fdt_entry->dir==NULL) {
    return -1;
  }

  struct thread* t = thread_current();
  fdt_entry->fd = t->pcb->max_fd++;
  list_push_back(&t->pcb->fdt, &fdt_entry->elem);

  return fdt_entry->fd;
}

int sys_file_size(int fd) {
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL || fdt_entry->is_dir) {
    return -1;
  }

  return file_length(fdt_entry->file);
}

int sys_read(int fd, void* buffer, unsigned size) {
  if (fd == 0) {
    char* input[size + 1];
    for (unsigned i = 0; i < size; i++) {
      input[i] = input_getc();
    }
    input[size] = '\0';
    memcpy(buffer, (void*)input, size + 1);
    return size;
  }

  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL || fdt_entry->is_dir) {
    return -1;
  }

  return file_read(fdt_entry->file, buffer, size);
}

int sys_write(int fd, void* buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);

    return size;
  }
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL || fdt_entry->is_dir) {
    return -1;
  }

  return file_write(fdt_entry->file, buffer, size);
}

void sys_seek(int fd, unsigned position) {
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL || fdt_entry->is_dir) {
    return;
  }

  file_seek(fdt_entry->file, position);
}

unsigned sys_tell(int fd) {
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL || fdt_entry->is_dir) {
    return -1;
  }

  return file_tell(fdt_entry->file);
}

void sys_close(int fd) {
  struct fdt_entry* fdt_entry = get_fdt_entry(fd);
  if (fdt_entry == NULL) {
    return;
  }

  if (fdt_entry->is_dir) {
    dir_close(fdt_entry->dir);
  }
  else {
    file_close(fdt_entry->file);
  }
  remove_fdt_entry(fd);
}

int sys_practice(int i) { return ++i; }

// Checks that each byte of the user buffer is valid
void check_arg_pointers(const char* arg_pointer) {
  char* arg_pointer_cpy = arg_pointer;
  if (arg_pointer_cpy == NULL) {
    sys_exit(-1);
  }

  while (true) {
    if (!is_user_vaddr((uint32_t*)arg_pointer_cpy)) {
      sys_exit(-1);
    } 
    else if (pagedir_get_page(thread_current()->pcb->pagedir, (const void*)arg_pointer_cpy) == NULL) {
      sys_exit(-1);
    }
    
    if (*arg_pointer_cpy == NULL) {
      break;
    }
    arg_pointer_cpy++;
  }
}

// Exits if user stack has invalid memory
void check_user_stack_addresses(uint32_t* uaddr, size_t num_bytes) {
  if (uaddr == NULL) {
    sys_exit(-1);
  }
  // Cast to char* so ++ operator increments ptr by one byte
  char* uaddr_cpy = (char*)uaddr;
  for (size_t i = 0; i < num_bytes; i++) {
    if (!is_user_vaddr((uint32_t*)uaddr_cpy)) {
      sys_exit(-1);
    } else if (pagedir_get_page(thread_current()->pcb->pagedir, (const void*)uaddr_cpy) == NULL) {
      sys_exit(-1);
    }
    uaddr_cpy++;
  }
}

// Gets file from file descriptor table
struct fdt_entry* get_fdt_entry(int fd) {
  if (fd == 0 || fd == 1) {
    return NULL;
  }

  struct process* cur_pcb = thread_current()->pcb;
  struct list_elem* e;
  struct fdt_entry* fdt_entry = NULL;
  for (e = list_begin(&cur_pcb->fdt); e != list_end(&cur_pcb->fdt); e = list_next(e)) {
    fdt_entry = list_entry(e, struct fdt_entry, elem);
    if (fdt_entry->fd == fd) {
      return fdt_entry;
    }
  }
  return NULL;
}

// Removes and frees entry from fdt
void remove_fdt_entry(int fd) {
  struct process* cur_pcb = thread_current()->pcb;
  struct list_elem* e;

  for (e = list_begin(&cur_pcb->fdt); e != list_end(&cur_pcb->fdt); e = list_next(e)) {
    struct fdt_entry* fdt_entry = list_entry(e, struct fdt_entry, elem);
    if (fdt_entry->fd == fd) {
      list_remove(&fdt_entry->elem);
      free(fdt_entry);
      return;
    }
  }
}