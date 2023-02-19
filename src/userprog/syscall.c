#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

// System calls
void sys_close(int fd);
bool sysc_create(const char *file, unsigned initial_size);
pid_t sys_exec(const char *cmd_line);
void sys_exit(int);
int sys_file_size(int fd);
void sys_halt(void);
int sys_open(const char *file);
int sys_practice(int i);
int sys_read(int fd, char *buffer, unsigned size);
bool sys_remove(const char *file);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
int sys_wait(pid_t pid);
int sys_write(int fd, const char *buffer, unsigned size);

// User pointer validation
void check_user_addresses(uint32_t* uaddr, size_t num_bytes);


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
  
  switch(args[0])
  {
    case SYS_CLOSE:
      // TODO
      break;
    case SYS_CREATE:
      // TODO
      break;
    case SYS_EXEC:
      // TODO
      break;
    case SYS_EXIT:
      //TODO
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      sys_exit(args[1]);
      break;
    case SYS_FILESIZE:
      // TODO
      break;
    case SYS_HALT:
      // TODO
      break;
    case SYS_OPEN:
      // TODO
      break;
    case SYS_PRACTICE:
      // TODO
      f->eax = sys_practice(args[1]);
      break;
    case SYS_READ:
      // TODO
      break;
    case SYS_REMOVE:
      // TODO
      break;
    case SYS_SEEK:
      // TODO
      break;
    case SYS_TELL:
      // TODO
      break;
    case SYS_WAIT:
      // TODO
      break;
    case SYS_WRITE:
      //TODO
      f->eax = sys_write(args[1], (const char*)args[2], args[3]);
      break;
  }
}



void sys_close(int fd) {
  // TODO
}

bool sysc_create(const char *file, unsigned initial_size) {
  // TODO
}
pid_t sys_exec(const char *cmd_line) {
  // TODO
}

void sys_exit(int status UNUSED) {
  // TODO
  process_exit();
}

int sys_file_size(int fd) {
  // TODO
}

void sys_halt() {
  // TODO
}

int sys_open(const char *file) {
  // TODO
}
int sys_practice(int i) {
  return ++i;
}

int sys_read(int fd, char *buffer, unsigned size) {
  // TODO
}

bool sys_remove(const char *file) {
  // TODO
}

void sys_seek(int fd, unsigned position) {
  // TODO
}

unsigned sys_tell(int fd) {
  // TODO
}

int sys_wait(pid_t pid) {
  // TODO
}

int sys_write(int fd, const char *buffer, unsigned size) {
  // TODO
  if (fd == 1)
  {
    putbuf(buffer, size);

    // Not sure what to return when writing to the console
    return size;
  }
  return 0;
}

void check_user_addresses(uint32_t* uaddr, size_t num_bytes) {
  // TODO
}