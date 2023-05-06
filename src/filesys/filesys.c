#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"

/* Partition that contains the file system. */
struct block* fs_device;

struct dir* resolve_path(char* name);
bool get_file_from_path(const char* path_ptr, char** dir_path, char** file_name);
static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  buffer_cache_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();

  struct dir* root = dir_open_root();
  thread_current()->pcb->cwd = root;
  dir_add(root, ".", ROOT_DIR_SECTOR, true);
  dir_add(root, "..", ROOT_DIR_SECTOR, true);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); buffer_cache_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  if (strlen(name) > NAME_MAX) {
    return false;
  }
  block_sector_t inode_sector = 0;
  bool is_dir = false;
  bool success;
  char* dir_path = (char*)malloc(strlen(name) + 1);
  char* file_name = (char*)malloc(NAME_MAX + 1);

  if (!get_file_from_path(name, &dir_path, &file_name)) {
    free(dir_path);
    free(file_name);
    return false;
  }
  struct dir* dir = resolve_path(dir_path);

  success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
             inode_create(inode_sector, initial_size, is_dir) &&
             dir_add(dir, file_name, inode_sector, is_dir));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);

  dir_close(dir);
  free(dir_path);
  free(file_name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  if (strlen(name) == 0) {
    return NULL;
  }

  char* dir_path = (char*)malloc(strlen(name) + 1);
  char* file_name = (char*)malloc(NAME_MAX + 1);
  get_file_from_path(name, &dir_path, &file_name);

  struct dir* dir = resolve_path(dir_path);
  if (dir == NULL) {
    free(dir_path);
    free(file_name);
    return NULL;
  }
  struct inode* inode;
  if (strlen(file_name) == 0) {
    inode = dir_get_inode(dir);
  } else {
    dir_lookup(dir, file_name, &inode);
  }
  
  dir_close(dir);
  free(dir_path);
  free(file_name);
  if (inode == NULL) {
    return NULL;
  }
  if (get_is_dir(inode)) {
    return (struct file*)dir_open(inode);
  }
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  if (name[0] == '/' && strlen(name) == 1) {
    return false;
  }
  bool success = false;
  char* dir_path = (char*)malloc(strlen(name) + 1);
  char* file_name = (char*)malloc(NAME_MAX + 1);
  get_file_from_path(name, &dir_path, &file_name);
  struct dir* dir = resolve_path(dir_path);
  if (dir == NULL) {
    free(dir_path);
    free(file_name);
    return success;
  }

  struct inode* inode = NULL;
  dir_lookup(dir, file_name, &inode);
  if (inode != NULL) {
    if (get_is_dir(inode)) {
      struct inode* cwd_inode = dir_get_inode(thread_current()->pcb->cwd);
      if (cwd_inode == inode || get_open_count(inode) > 1 || get_num_entries(inode)) {
        goto done;
      }
    }
    success = dir_remove(dir, file_name);
  }

done:
  free(file_name);
  free(dir_path);
  dir_close(dir);
  inode_close(inode);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

bool get_file_from_path(const char* path_ptr, char** dir_path, char** file_name) {
  char* path = path_ptr;
  char* dir = *dir_path;
  char* file = *file_name;
  char part[NAME_MAX + 1];
  if (path[0] == '/') {
    dir[0] = '/';
    dir += 1;
  }
  int success = get_next_part(part, &path);
  char* slash = "/";
  if (!success) {
    file[0] = '\0';
    dir[0] = '\0';
    return true;
  }

  while (path[0] != '\0' && success) {
    memcpy(dir, part, strlen(part));
    dir += strlen(part);
    memcpy(dir, slash, sizeof(char));
    dir += 1;
    success = get_next_part(part, &path);
  }
  dir[0] = '\0';
  memcpy(file, part, strlen(part) + 1);

  return success;
}

struct dir* resolve_path(char* name) {
  struct dir* curr_dir;
  struct inode* inode;
  bool success;
  if (name[0] == '/') {
    curr_dir = dir_open_root();
  } else {
    curr_dir = dir_reopen(thread_current()->pcb->cwd);
  }
  char part[NAME_MAX + 1];

  while (get_next_part(part, &name)) {
    success = dir_lookup(curr_dir, part, &inode);
    if (success) {
      dir_close(curr_dir);
      curr_dir = dir_open(inode);
    } else {
      dir_close(curr_dir);
      inode_close(inode);
      return NULL;
    }
  }
  return curr_dir;
}

////////////////////////////////////
//////////NEW SYSCALLS//////////////
////////////////////////////////////

bool filesys_mkdir(const char* name) {
  bool success;
  block_sector_t inode_sector = 0;
  int initial_size = 2;
  bool is_dir = true;
  char* dir_path = (char*)malloc(strlen(name) + 1);
  char* new_dir_name = (char*)malloc(NAME_MAX + 1);
  success = get_file_from_path(name, &dir_path, &new_dir_name);
  if (!success) {
    free(dir_path);
    free(new_dir_name);
    return success;
  }
  struct dir* dir = resolve_path(dir_path);
  if (dir == NULL) {
    free(dir_path);
    free(new_dir_name);
    return false;
  }

  success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
             inode_create(inode_sector, initial_size, is_dir) &&
             dir_add(dir, new_dir_name, inode_sector, is_dir));
  if (!success && inode_sector != 0) {
    free_map_release(inode_sector, 1);
  } else if (success) {
    //ADDING . and .. dir entries
    dir_create(inode_sector, 2);
    struct inode* inode = inode_open(inode_sector);
    struct dir* new_dir = dir_open(inode);

    dir_add(new_dir, ".", inode_sector, true);
    struct inode* parent_inode = dir_get_inode(dir);
    block_sector_t parent_sector = inode_get_inumber(parent_inode);
    dir_add(new_dir, "..", parent_sector, true);
    dir_close(new_dir);
  }
  dir_close(dir);
  free(dir_path);
  free(new_dir_name);

  return success;
}
bool filesys_chdir(const char* name) {
  bool success = false;
  struct inode* inode = NULL;
  char* dir_path = (char*)malloc(strlen(name) + 1);
  char* dir_name = (char*)malloc(NAME_MAX + 1);
  get_file_from_path(name, &dir_path, &dir_name);
  struct dir* dir = resolve_path(dir_path);
  if (dir == NULL) {
    goto done;
  }

  if (strlen(dir_name) == 0) {
    inode = dir_get_inode(dir);
  } else {
    dir_lookup(dir, dir_name, &inode);
  }

  struct dir* prev_cwd = thread_current()->pcb->cwd;
  if (inode != NULL && get_is_dir(inode)) {
    /* Close previous directory*/
    if (prev_cwd != dir) {
      dir_close(prev_cwd);
    } else {
      /* dir will get freed when dir_close is called */
      inode_close(dir_get_inode(prev_cwd));
    }
    /* Open new directory. */
    thread_current()->pcb->cwd = dir_open(inode);
    success = true;
  } else {
    goto done;
  }

  if (dir_get_inode(dir) != inode || prev_cwd == dir) {
    dir_close(dir);
  }

done:
  free(dir_path);
  free(dir_name);
  return success;
}
