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

/* Partition that contains the file system. */
struct block* fs_device;

struct dir* resolve_path(char* name);
char* get_file_from_path(const char* path_ptr, char** dir_path, char** file_name);
static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
  //TODO Add '.' and '..' entries
  struct dir* root = dir_open_root();
  thread_current()->pcb->cwd = root;
  // dir_add(root, ".", ROOT_DIR_SECTOR, true);
  // dir_add(root, "..", ROOT_DIR_SECTOR, true);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  // struct dir* dir = dir_open_root();

  char* dir_path = (char*) malloc(strlen(name)+1);
  char* file_name = (char *) malloc(NAME_MAX+1);
  get_file_from_path(name, &dir_path, &file_name);
  struct dir* dir = resolve_path(dir_path);
  // free(dir_path);
  // free(file_name);

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector, false));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  //TODO Set created inode_disk is_dir = false
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  //TODO Resolve path. Get inode from path. If inode_disk->is_dir = true, return dir_open()
  
  struct dir* dir = resolve_path(name);
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  //################//
  //TODO Resolve path.
  //if is_dir:
      //if name == "/", '.', or '..': error. can't delete root dir
        // if dir open_cnt > 0: return false 
        // if dir is_cwd: return false
        // if dir has entries other than '.' and '..': return false
        // else: dir_remove()
  //else: call normally
  //################//

  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

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

char* get_file_from_path(const char* path_ptr, char** dir_path, char** file_name) {
    char* path = path_ptr;
    char* dir = *dir_path;
    char* file = *file_name;
    char part[NAME_MAX + 1];
    if (path[0] == '/') {dir[0]='/';dir+=1;}
    int success = get_next_part(part,&path);
    char* slash = "/";
  
    while(path[0] != '\0') {
      memcpy(dir, part, strlen(part));
      dir += strlen(part);
      memcpy(dir,slash,sizeof(char));
      dir += 1;
      success = get_next_part(part,&path);
  }
  dir[0]='\0';
  memcpy(file, part, strlen(part)+1);
  
  return;
}

struct dir* resolve_path(char* name) {
  struct dir* curr_dir;
  struct inode* inode = (struct inode*) malloc(sizeof(inode));
  int x = strlen(name);
  // struct inode_disk* inode_disk;
  bool success;
  if (name[0] == "/" || strlen(name)==0) {
    curr_dir = dir_open_root();
  }
  else {
    curr_dir = thread_current()->pcb->cwd;
  }
  char part[NAME_MAX +1];

  while (get_next_part(part, &name)) {
    success = dir_lookup(curr_dir, part, &inode);
    if (success) {
      curr_dir = dir_open(inode);
    }
    else {
      printf("error");
    }
  }
  return curr_dir;
  //Don't forget to free inode_disk
}
