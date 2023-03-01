#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, char* args, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);
void push_arguments(const char* args, void** esp);
int calculate_alignment(int offset, int argc);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;
  list_init(&(t->pcb->children));
  lock_init(&(t->pcb->child_list_lock));
  // struct shared_data_struct* shared_data = (struct shared_data_struct*) malloc(sizeof(struct shared_data_struct));
  // shared_data->ref_count = 2;
  // t->pcb->shared_data = shared_data;

  lock_init(&fileop_lock);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

struct process* create_child_pcb() {
  bool success, pcb_success;
  struct process* new_pcb = (struct process*)malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;
  if (success) {
    struct thread* parent = thread_current();
    new_pcb->pagedir = NULL;
    list_init(&(new_pcb->children));
    lock_init(&(new_pcb->child_list_lock));

    list_init(&(new_pcb->fdt));
    new_pcb->max_fd = 2;

    pid_t pid;
  }
  return new_pcb;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  // sema_init(&temporary, 0);
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  // char* tmp = malloc(strlen((char*)file_name) + 1);
  char tmp[strlen(file_name) + 1];
  strlcpy(tmp, file_name, strlen(file_name) + 1);

  char* tmpPointer;
  file_name = strtok_r(tmp, " ", &tmpPointer);

  struct process* child_pcb = create_child_pcb();

  //Creating struct to pass into start_process
  struct shared_data_struct* start_process_args =
      (struct shared_data_struct*)malloc(sizeof(struct shared_data_struct));
  start_process_args->pcb = child_pcb;
  start_process_args->fn_copy = fn_copy;
  start_process_args->shared_data_status = -1;
  start_process_args->ref_count = 2;
  start_process_args->parent_waiting = false;
  start_process_args->load_status = -1;

  sema_init(&(start_process_args->shared_data_sema), 0);
  lock_init(&(start_process_args->shared_data_lock));

  //Add shared_data struct to parent/my pcb list
  struct process* parent_pcb = thread_current()->pcb;
  lock_acquire(&(parent_pcb->child_list_lock));
  struct list* parents_children_list = &(parent_pcb->children);
  struct list_elem new_elem;
  start_process_args->elem = new_elem;

  size_t num_elems = list_size(parents_children_list);
  list_push_front(parents_children_list, &(start_process_args->elem));
  num_elems = list_size(parents_children_list);
  lock_release(&(parent_pcb->child_list_lock));

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, (void*)start_process_args);

  //Parent waiting until load happens and child process calls sema_up
  sema_down(&(start_process_args->shared_data_sema));

  //Check if child errored on load
  lock_acquire(&(start_process_args->shared_data_lock));
  if (start_process_args->load_status == -1) {
    lock_release(&(start_process_args->shared_data_lock));
    return -1;
  }
  start_process_args->pid = tid;
  start_process_args->pcb->pid = tid;
  lock_release(&(start_process_args->shared_data_lock));

  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* start_process_args) {
  //Cast void * input, and get variables from struct
  struct shared_data_struct* args_struct = start_process_args;
  char* file_name_ = args_struct->fn_copy;
  struct process* pcb = args_struct->pcb;

  // Copy since strtok_r changes string
  char tmp[strlen(file_name_) + 1];
  strlcpy(tmp, file_name_, strlen(file_name_) + 1);

  char* tmpPointer;
  char* file_name = strtok_r(tmp, " ", &tmpPointer);
  char* args = (char*)file_name_;

  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  success = pcb_success = pcb != NULL;

  /* Initialize process control block */

  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    t->pcb = pcb;
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, args, &if_.eip, &if_.esp);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }
  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(args);
  if (!success) {
    // printf("%s\n", "Failed to free page");
    lock_acquire(&args_struct->shared_data_lock);
    sema_up(&(args_struct->shared_data_sema));
    //args_struct->shared_data_status already initialized to -1
    lock_release(&args_struct->shared_data_lock);
    thread_exit();
  }

  //Program loaded properly. Let the parent know.
  lock_acquire(&(args_struct->shared_data_lock));
  pcb->shared_data = args_struct;
  args_struct->load_status = 0;
  lock_release(&(args_struct->shared_data_lock));
  sema_up(&(args_struct->shared_data_sema));

  // Initalize fpu register for user process
  uint8_t temp_fpu_state[108];
  asm volatile("fsave (%0); fninit; fsave (%1); frstor (%2)"
               :
               : "g"(&temp_fpu_state), "g"(&if_.fpu_state), "g"(&temp_fpu_state));

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  // sema_down(&temporary);
  struct thread* cur = thread_current();
  struct process* my_pcb = cur->pcb;
  struct list* my_children = &(my_pcb->children);
  struct list_elem* e;
  lock_acquire(&(my_pcb->child_list_lock));
  e = list_begin(my_children);
  while (e != list_end(my_children)) {
    struct shared_data_struct* child = list_entry(e, struct shared_data_struct, elem);
    lock_acquire(&(child->shared_data_lock));
    if (child->pid == child_pid) {
      if (child->parent_waiting == true) {
        lock_release(&(my_pcb->child_list_lock));
        lock_release(&(child->shared_data_lock));
        return -1;
      } else {
        child->parent_waiting = true;
        lock_release(&(child->shared_data_lock));
        sema_down(&(child->shared_data_sema));
        lock_acquire(&(child->shared_data_lock));
        int exit_status = child->shared_data_status;
        child->ref_count -= 1;
        ASSERT(child->ref_count == 0);
        if (child->ref_count == 0) {
          //MIGHT NEED TO PUT LIST LOCK HERE
          e = list_remove(&(child->elem));
          lock_release(&(child->shared_data_lock));
          lock_release(&(my_pcb->child_list_lock));
          free(child);
        } else {
          lock_release(&(child->shared_data_lock));
          lock_release(&(my_pcb->child_list_lock));
        }
        return exit_status;
      }
    } else {
      lock_release(&(child->shared_data_lock));
      e = list_next(e);
    }
    //MIGHT NEED TO RELEASE CHILD LOCK HERE TOO. NOT SURE
  }
  lock_release(&(my_pcb->child_list_lock));
  return -1;
}

/* Free the current process's resources. */
void process_exit() {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  //Check children.  If ref_count == 0, free shared data.  Else: decrement ref_count of child
  struct process* my_pcb = cur->pcb;
  struct list* my_children = &(my_pcb->children);
  struct list_elem* e;
  struct shared_data_struct* shared_data = my_pcb->shared_data;
  printf("%s: exit(%d)\n", cur->pcb->process_name, shared_data->shared_data_status);

  lock_acquire(&(my_pcb->child_list_lock));

  e = list_begin(my_children);
  while (e != list_end(my_children)) {
    struct shared_data_struct* child = list_entry(e, struct shared_data_struct, elem);
    lock_acquire(&(child->shared_data_lock));
    child->ref_count -= 1;
    if (child->ref_count == 0) {
      e = list_remove(&(child->elem));
      // MIGHT NEED TO ADD THIS LINE LATER lock_release(&(child->shared_data_lock));
      free(child);
    } else {
      lock_release(&(child->shared_data_lock));
      e = list_next(e);
    }
    // lock_release(&(child->shared_data_lock));
  }
  lock_release(&(cur->pcb->child_list_lock));

  lock_acquire(&(shared_data->shared_data_lock));
  shared_data->ref_count -= 1;
  if (shared_data->ref_count == 0) {
    lock_release(&(shared_data->shared_data_lock));
    free(shared_data);
  } else {
    lock_release(&(shared_data->shared_data_lock));
    sema_up(&(shared_data->shared_data_sema));
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  // Lock might be held if exiting from a file syscall
  if (!lock_held_by_current_thread(&fileop_lock)) {
    lock_acquire(&fileop_lock);
  }

  // Allow write
  struct file* executable = cur->pcb->executable;
  if (executable != NULL) {
    file_close(cur->pcb->executable);
  }
  lock_release(&fileop_lock);

  close_and_remove_all_files();

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  thread_exit();
}

void close_and_remove_all_files(void) {
  struct process* cur_pcb = thread_current()->pcb;
  struct list_elem* e;

  while (!list_empty(&cur_pcb->fdt)) {
    e = list_pop_front(&cur_pcb->fdt);
    struct fdt_entry* fdt_entry = list_entry(e, struct fdt_entry, elem);

    lock_acquire(&fileop_lock);
    file_close(fdt_entry->file);
    lock_release(&fileop_lock);

    list_remove(&fdt_entry->elem);
    free(fdt_entry);
  }
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(const char* file_name, void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, char* args, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  t->pcb->executable = file;

  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  // Deny write
  lock_acquire(&fileop_lock);
  file_deny_write(file);
  lock_release(&fileop_lock);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(args, esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(const char* args, void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      *esp = PHYS_BASE;
      push_arguments(args, esp);
    } else
      palloc_free_page(kpage);
  }
  return success;
}

void push_arguments(const char* args, void** esp) {
  void* esp_original = *esp;
  char* arg;
  char* rest = args;
  char* argv[64]; // User stack pointers

  int argc = 0;
  while (arg = strtok_r(rest, " ", &rest)) {
    *esp -= strlen(arg) + 1;
    memcpy(*esp, (void*)arg, strlen(arg) + 1);
    argv[argc] = (char*)*esp;
    argc++;
  }

  // Stack align
  int stack_align = calculate_alignment(esp_original - *esp, argc);
  *esp -= stack_align;
  memset(*esp, 0, stack_align);

  // Push null pointer at argv[4]
  *esp -= 4;
  memset(*esp, 0, 4);

  // Push arg addresses
  for (int i = argc - 1; i >= 0; i--) {
    *esp -= 4;
    *(char**)*esp = argv[i];
  }

  // Push argv (address of arg[0])
  void* esp_tmp = *esp;
  *esp -= 4;
  *(char**)*esp = esp_tmp;

  // Push argc
  *esp -= 4;
  *(int*)*esp = argc;

  // Fake return
  *esp -= 4;
  *(char**)*esp = 0;
}

int calculate_alignment(int offset, int argc) {
  int x = offset + ((argc + 3) * 4);
  if (x % 16 == 0) {
    return 0;
  }
  int aligned = ((x - 1) | 15) + 1;
  return aligned - x;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED) { return false; }

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { return -1; }

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { return -1; }

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
