#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define INODE_DIRECT 123
#define BLOCK_POINTERS_PER_SECTOR 128

struct lock inode_list_lock;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  block_sector_t direct_ptrs[INODE_DIRECT];
  block_sector_t single_indirect_ptr;
  block_sector_t double_indirect_ptr;
  //TODO Add is_dir. Check if need to decrease num direct pointers
  bool is_dir;
  char unused[3];
};

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock;
  struct lock resize_lock;
  bool is_dir;
};

static bool inode_resize(struct inode_disk*, off_t size);
static bool inode_allocate(struct inode_disk*, size_t sectors);
static void inode_free(struct inode_disk*, size_t sectors);

struct inode_disk* get_disk_inode(struct inode* inode) {
  struct inode_disk* id = malloc(sizeof(struct inode_disk));
  if (id == NULL) {
    return NULL;
  }
  block_read(fs_device, inode->sector, id);
  return id;
}

bool get_is_dir(struct inode* inode) {
  return inode->is_dir;
}

int get_open_count(struct inode* inode) {
  return inode->open_cnt;
}


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(struct inode_disk* id, off_t pos) {
  ASSERT(id != NULL);

  if (pos < id->length) {
    size_t block_index = pos / BLOCK_SECTOR_SIZE;
    if (block_index < INODE_DIRECT) {
      // Direct blocks
      return id->direct_ptrs[block_index];
    } else {
      // Indirect blocks
      block_index -= INODE_DIRECT;
      if (block_index < BLOCK_POINTERS_PER_SECTOR) {
        block_sector_t* indirect_block = malloc(BLOCK_SECTOR_SIZE);
        ASSERT(indirect_block != NULL);
        block_read(fs_device, id->single_indirect_ptr, indirect_block);
        block_sector_t sector = indirect_block[block_index];
        free(indirect_block);
        return sector;
      } else {
        // Double indirect
        block_index -= BLOCK_POINTERS_PER_SECTOR;
        size_t double_index = block_index / BLOCK_POINTERS_PER_SECTOR; // Index into double indirect block
        size_t single_index = block_index % BLOCK_POINTERS_PER_SECTOR; // Index into single indirect block

        block_sector_t* double_indirect_block = malloc(BLOCK_SECTOR_SIZE);
        ASSERT(double_indirect_block != NULL);
        block_read(fs_device, id->double_indirect_ptr, double_indirect_block);

        block_sector_t single_indirect_ptr = double_indirect_block[double_index];

        block_sector_t* single_indirect_block = malloc(BLOCK_SECTOR_SIZE);
        ASSERT(single_indirect_block != NULL);
        block_read(fs_device, single_indirect_ptr, single_indirect_block);

        block_sector_t sector = single_indirect_block[single_index];
        free(double_indirect_block);
        free(single_indirect_block);
        return sector;
      }
    }
  } else {
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&inode_list_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->is_dir = is_dir;
    if (inode_allocate(disk_inode, sectors)) {
      block_write(fs_device, sector, disk_inode);
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

bool inode_allocate(struct inode_disk* id, size_t sectors) {
  static char zeros[BLOCK_SECTOR_SIZE];
  size_t sectors_to_allocate = sectors < INODE_DIRECT ? sectors : INODE_DIRECT;
  size_t i;
  size_t sectors_allocated = 0;

  /* Allocate sectors for direct pointers */
  for (i = 0; i < sectors_to_allocate; i++) {
    if (!free_map_allocate(1, &id->direct_ptrs[i])) {
      inode_free(id, sectors_allocated);
      return false;
    }
    // Zero out
    block_write(fs_device, id->direct_ptrs[i], zeros);
    sectors_allocated++;
  }

  /* Check if we need to allocate a indirect block */
  if (sectors > INODE_DIRECT) {
    sectors -= INODE_DIRECT;
    
    // Allocate indirect block
    if (!free_map_allocate(1, &id->single_indirect_ptr)) {
      inode_free(id, sectors_allocated);
      return false;
    }
    sectors_allocated++;
    
    sectors_to_allocate = sectors < BLOCK_POINTERS_PER_SECTOR ? sectors : BLOCK_POINTERS_PER_SECTOR;
    block_sector_t* indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
    ASSERT(indirect_block != NULL);
    for (i = 0; i < sectors_to_allocate; i++) {
      if (!free_map_allocate(1, &indirect_block[i])) {
        inode_free(id, sectors_allocated);
        return false;
      }
      // Zero out
      block_write(fs_device, indirect_block[i], zeros);
      sectors_allocated++;
    }
    // Write indirect block to disk
    block_write(fs_device, id->single_indirect_ptr, indirect_block);
    free(indirect_block);

    /* Check if we need to allocate a double indirect block. */
    if (sectors > BLOCK_POINTERS_PER_SECTOR) {
      sectors -= BLOCK_POINTERS_PER_SECTOR;

      // Allocate double indirect block
      if (!free_map_allocate(1, &id->double_indirect_ptr)) {
        inode_free(id, sectors_allocated);
        return false;
      }
      sectors_allocated++;

      // Allocate indirect blocks for double indirect block
      block_sector_t* double_indirect_block = calloc(1, BLOCK_POINTERS_PER_SECTOR);
      ASSERT(double_indirect_block != NULL);
      size_t num_indirect_blocks = DIV_ROUND_UP(sectors, BLOCK_POINTERS_PER_SECTOR);
      size_t j;
      for (i = 0; i < num_indirect_blocks; i++) {
        // Allocate indirect block
        if (!free_map_allocate(1, &double_indirect_block[i])) {
          inode_free(id, sectors_allocated);
          return false;
        }
        sectors_allocated++;
        
        // Allocate sectors for indirect blocks
        sectors_to_allocate = sectors < BLOCK_POINTERS_PER_SECTOR ? sectors : BLOCK_POINTERS_PER_SECTOR;
        block_sector_t* indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
        ASSERT(indirect_block != NULL);
        for (j = 0; j < sectors_to_allocate; j++) {
          if (!free_map_allocate(1, &indirect_block[j])){
            inode_free(id, sectors_allocated);
            return false;
          }
          // Zero out
          block_write(fs_device, indirect_block[i], zeros);
          sectors_allocated++;
        }
        // Write indirect block to disk
        block_write(fs_device, double_indirect_block[i], indirect_block);
        free(indirect_block);
        if (sectors > BLOCK_POINTERS_PER_SECTOR) {
          sectors -= BLOCK_POINTERS_PER_SECTOR;
        }
      }

      // Write double indirect block to disk
      block_write(fs_device, id->double_indirect_ptr, double_indirect_block);
      free(double_indirect_block);
    }
  }
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  lock_acquire(&inode_list_lock);
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      lock_release(&inode_list_lock);
      inode_reopen(inode);
      return inode;
    }
  }
  lock_release(&inode_list_lock);

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_acquire(&inode_list_lock);
  list_push_front(&open_inodes, &inode->elem);
  lock_release(&inode_list_lock);

  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);
  lock_init(&inode->resize_lock);
  //Is this okay?!
  struct inode_disk* id = get_disk_inode(inode);
  inode->is_dir = id->is_dir;
  free(id);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    lock_acquire(&inode->inode_lock);
    inode->open_cnt++;
    lock_release(&inode->inode_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  lock_acquire(&inode->inode_lock);
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release inode lock acquire list lock. */
    lock_release(&inode->inode_lock);

    lock_acquire(&inode_list_lock);
    list_remove(&inode->elem);
    lock_release(&inode_list_lock);

    /* Deallocate blocks if removed. */
    lock_acquire(&inode->inode_lock);
    if (inode->removed) {
      lock_release(&inode->inode_lock);
      struct inode_disk* id = get_disk_inode(inode);
      ASSERT(id != NULL);
      free_map_release(inode->sector, 1);
      inode_free(id, bytes_to_sectors(id->length));
      free(id);
    } else {
      lock_release(&inode->inode_lock);
    }
    free(inode);
  } else {
    lock_release(&inode->inode_lock);
  }
}

void inode_free(struct inode_disk* id, size_t sectors) {
  size_t sectors_to_free = sectors < INODE_DIRECT ? sectors : INODE_DIRECT;
  size_t i;
  for (i = 0; i < sectors_to_free; i++) {
    free_map_release(id->direct_ptrs[i], 1);
  }
  if (sectors > INODE_DIRECT) {
    sectors -= INODE_DIRECT;
    
    // Get indirect block
    block_sector_t* indirect_block = malloc(BLOCK_SECTOR_SIZE);
    ASSERT(indirect_block != NULL);
    block_read(fs_device, id->single_indirect_ptr, indirect_block);

    // Free indirect block
    free_map_release(id->single_indirect_ptr, 1);
    
    sectors_to_free = sectors < BLOCK_POINTERS_PER_SECTOR ? sectors : BLOCK_POINTERS_PER_SECTOR;
    for (i = 0; i < sectors_to_free; i++) {
      free_map_release(indirect_block[i], 1);
    }
    free(indirect_block);

    if (sectors > BLOCK_POINTERS_PER_SECTOR) {
      sectors -= BLOCK_POINTERS_PER_SECTOR;

      // Get double indirect block
      block_sector_t* double_indirect_block = malloc(BLOCK_SECTOR_SIZE);
      ASSERT(double_indirect_block != NULL);
      block_read(fs_device, id->double_indirect_ptr, double_indirect_block);

      // Free double indirect block
      free_map_release(id->double_indirect_ptr, 1);

      size_t num_indirect_blocks = DIV_ROUND_UP(sectors, BLOCK_POINTERS_PER_SECTOR);
      size_t j;
      for (i = 0; i < num_indirect_blocks; i++) {
        // Get indirect block
        block_sector_t* indirect_block = malloc(BLOCK_SECTOR_SIZE);
        ASSERT(indirect_block != NULL);
        block_read(fs_device, double_indirect_block[i], indirect_block);

        sectors_to_free = sectors < BLOCK_POINTERS_PER_SECTOR ? sectors : BLOCK_POINTERS_PER_SECTOR;
        for (j = 0; j < sectors_to_free; j++) {
          free_map_release(indirect_block[j], 1);
        }

        free(indirect_block);
        if (sectors > BLOCK_POINTERS_PER_SECTOR) {
          sectors -= BLOCK_POINTERS_PER_SECTOR;
        }
      }

      free(double_indirect_block);
    }
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);

  lock_acquire(&inode->inode_lock);
  inode->removed = true;
  lock_release(&inode->inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  struct inode_disk* id = get_disk_inode(inode);
  ASSERT(id != NULL);

  lock_acquire(&inode->resize_lock);
  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(id, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = id->length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);
  free(id);
  lock_release(&inode->resize_lock);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  lock_acquire(&inode->inode_lock);
  if (inode->deny_write_cnt) {
    lock_release(&inode->inode_lock);
    return 0;
  }
  lock_release(&inode->inode_lock);

  struct inode_disk* id = get_disk_inode(inode);
  ASSERT(id != NULL);

  lock_acquire(&inode->resize_lock);
  if (offset + size > id->length) {
    if (!inode_resize(id, offset + size)) {
      lock_release(&inode->resize_lock);
      return 0;
    }
    block_write(fs_device, inode->sector, id);
  }
  
  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(id, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = id->length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);
  free(id);
  lock_release(&inode->resize_lock);

  return bytes_written;
}

bool inode_resize(struct inode_disk* id, off_t size) {
  static char zeros[BLOCK_SECTOR_SIZE];
  /* Handle direct pointers. */
  for (int i = 0; i < INODE_DIRECT; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && id->direct_ptrs[i] != 0) {
      /* Shrink. */
      free_map_release(id->direct_ptrs[i], 1);
      id->direct_ptrs[i] = 0;
    } else if (size > BLOCK_SECTOR_SIZE * i && id->direct_ptrs[i] == 0) {
      /* Grow. */
      if(!free_map_allocate(1, &id->direct_ptrs[i])) {
        inode_resize(id, id->length);
        return false;
      }
      block_write(fs_device, id->direct_ptrs[i], zeros);
    }
  }


  /* Check if indirect pointers are needed. */
  if (size <= INODE_DIRECT * BLOCK_SECTOR_SIZE) {
    if (id->single_indirect_ptr != 0) {
      free_map_release(id->single_indirect_ptr, 1);
    }
    id->length = size;
    return true;
  }

  block_sector_t* indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
  ASSERT(indirect_block != NULL);
  if (id->single_indirect_ptr == 0) {
    /* Allocate indirect block. */
    if (!free_map_allocate(1, &id->single_indirect_ptr)) {
      inode_resize(id, id->length);
      return false;
    }
  } else {
    /* Read in indirect block. */
    block_read(fs_device, id->single_indirect_ptr, indirect_block);
  }
  
  /* Handle indirect pointers. */
  for (int i = 0; i < BLOCK_POINTERS_PER_SECTOR; i++) {
    if (size <= (INODE_DIRECT + i) * BLOCK_SECTOR_SIZE && indirect_block[i] != 0) {
      /* Shrink. */
      free_map_release(indirect_block[i], 1);
      indirect_block[i] = 0;
    } else if (size > (INODE_DIRECT + i) * BLOCK_SECTOR_SIZE && indirect_block[i] == 0) {
      /* Grow. */
      if (!free_map_allocate(1, &indirect_block[i])) {
        inode_resize(id, id->length);
        return false;
      }
      block_write(fs_device, indirect_block[i], zeros);
    }
  }

  /* Write the updates to the indirect block back to disk. */
  block_write(fs_device, id->single_indirect_ptr, indirect_block);
  free(indirect_block);

  //TODO handle double indirect block

  id->length = size;
  return true;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
  struct inode_disk id;
  block_read(fs_device, inode->sector, &id);
  return id.length; 
}