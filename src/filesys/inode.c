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
#define BUFFER_CACHE_SIZE 64

static int num_hits;

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
  bool is_dir;
};

/* Buffer cache entry stored in memory. */
struct buffer_cache_entry {
  struct list_elem elem;                // Element in buffer cache list
  uint8_t contents[BLOCK_SECTOR_SIZE];  // Buffer contents
  block_sector_t sector;                // Location on disk
  bool dirty;                           // Flag to indicate if contents in entry are dirty
  bool in_use;                          // Flag to indicate if in use
  struct lock entry_lock;               // Per entry lock
};

static bool inode_resize(struct inode_disk*, block_sector_t inode_sector, off_t size);

struct inode_disk* get_disk_inode(struct inode* inode) {
  return (struct inode_disk*)cache_read(fs_device, inode->sector);
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
static block_sector_t byte_to_sector(struct inode* inode, off_t pos) {
  struct inode_disk* id = get_disk_inode(inode);

  if (pos < id->length) {
    size_t block_index = pos / BLOCK_SECTOR_SIZE;
    if (block_index < INODE_DIRECT) {
      // Direct blocks
      return id->direct_ptrs[block_index];
    } else {
      // Indirect blocks
      block_index -= INODE_DIRECT;
      if (block_index < BLOCK_POINTERS_PER_SECTOR) {
        block_sector_t* indirect_block = (block_sector_t*)cache_read(fs_device, id->single_indirect_ptr);
        block_sector_t sector = indirect_block[block_index];
        return sector;
      } else {
        // Double indirect
        block_index -= BLOCK_POINTERS_PER_SECTOR;
        size_t double_index = block_index / BLOCK_POINTERS_PER_SECTOR; // Index into double indirect block
        size_t single_index = block_index % BLOCK_POINTERS_PER_SECTOR; // Index into single indirect block

        block_sector_t* double_indirect_block = cache_read(fs_device, id->double_indirect_ptr);

        block_sector_t single_indirect_ptr = double_indirect_block[double_index];

        block_sector_t* single_indirect_block = cache_read(fs_device, single_indirect_ptr);

        block_sector_t sector = single_indirect_block[single_index];
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

/* Associated lock */
static struct lock inode_list_lock;

/* Buffer cache */
struct list buffer_cache;

/* Associated lock. */
struct lock buffer_cache_lock;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  list_init(&buffer_cache);
  lock_init(&inode_list_lock);
  lock_init(&buffer_cache_lock);
}

/* Initializes buffer cache */
void buffer_cache_init(void) {
  for (size_t i = 0; i < BUFFER_CACHE_SIZE; i++) {
    struct buffer_cache_entry* entry = malloc(sizeof(struct buffer_cache_entry));
    if (entry == NULL) {
      PANIC("failed creating buffer cache");
    }
    
    entry->in_use = false;
    entry->dirty = false;
    lock_init(&entry->entry_lock);
    list_push_back(&buffer_cache, &entry->elem);
    num_hits = 0;
  }
}

/* Frees memory associated with buffer cache, writing back dity entries to disk */
void buffer_cache_close(void) {
  struct buffer_cache_entry* entry;

  lock_acquire(&buffer_cache_lock);
  while (!list_empty(&buffer_cache)) { 
    entry = list_entry(list_pop_front(&buffer_cache), struct buffer_cache_entry, elem);
    if (entry->dirty) {
      block_write(fs_device, entry->sector, entry->contents);
    }
    free(entry);
  }
  lock_release(&buffer_cache_lock);
}

/* Flushes buffer cache, writing dirty entries back to disk */
void buffer_cache_flush(void) {
  struct list_elem* e;
  struct buffer_cache_entry* entry;

  lock_acquire(&buffer_cache_lock);
  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    entry = list_entry(e, struct buffer_cache_entry, elem);
    /* Reset entry */
    if (entry->dirty) {
      block_write(fs_device, entry->sector, entry->contents);
    }
    entry->in_use = false;
    entry->dirty = false;
  }
  num_hits = 0;
  lock_release(&buffer_cache_lock);
}

/* Reads SIZE bytes from the buffer cache at SECTOR starting at 
   OFFSET. */
void* cache_read(struct block* fs_device, block_sector_t sector) {
  struct list_elem* e;
  struct buffer_cache_entry* entry;
  struct buffer_cache_entry* free_entry;
  bool full = true;

  /* Check if sector in cache */
  lock_acquire(&buffer_cache_lock);
  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    entry = list_entry(e, struct buffer_cache_entry, elem);
    if (entry->in_use) {
      if (entry->sector == sector) {
        /* Move entry to front of list */
        list_remove(e);
        list_push_front(&buffer_cache, &entry->elem);

        num_hits += 1;
        
        /* Release lock */
        lock_release(&buffer_cache_lock);

        return entry->contents;
      }
    } else {
        if (full) {
          free_entry = entry;
          full = false;
        }
      }
  }


  if (full) {
    /* If the cache is full we must evict the LRU entry. */
    entry = list_entry(e = list_pop_back(&buffer_cache), struct buffer_cache_entry, elem);

    /* Check if dirty. */
    if (entry->dirty) {
      /* Release global lock so we don't block */
      lock_release(&buffer_cache_lock);
      lock_acquire(&entry->entry_lock);
  
      block_write(fs_device, entry->sector, entry->contents);

      lock_release(&entry->entry_lock);
      lock_acquire(&buffer_cache_lock);
    }
  } else {
    entry = free_entry;
    list_remove(&entry->elem);
  }

  /* Read in sector from disk */
  entry->sector = sector;
  entry->dirty = false;
  entry->in_use = true;

  /* Release global lock acquire per entry lock */
  lock_release(&buffer_cache_lock);
  lock_acquire(&entry->entry_lock);

  block_read(fs_device, sector, entry->contents);

  lock_release(&entry->entry_lock);
  lock_acquire(&buffer_cache_lock);

  /* Push entry to front since MRU */
  list_push_front(&buffer_cache, &entry->elem);
  
  lock_release(&buffer_cache_lock);

  return entry->contents;
}

/* Writes SIZE bytes to the buffer cache at SECTOR starting at 
   OFFSET. */
void cache_write(struct block* fs_device, block_sector_t sector, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  struct list_elem* e;
  struct buffer_cache_entry* entry;
  struct buffer_cache_entry* free_entry;
  bool full = true;

  /* Check if sector in cache */
  lock_acquire(&buffer_cache_lock);
  for (e = list_begin(&buffer_cache); e != list_end(&buffer_cache); e = list_next(e)) {
    entry = list_entry(e, struct buffer_cache_entry, elem);
    if (entry->in_use) {
      if (entry->sector == sector) {
        /* Copy contents from user buffer into cache*/
        memcpy(entry->contents + offset, buffer, size);

        /* Move entry to front of list */
        list_remove(e);
        list_push_front(&buffer_cache, &entry->elem);

        /* Mark as dirty */
        entry->dirty = true;

        /* Release lock */
        lock_release(&buffer_cache_lock);
        return;
      }
    } else {
        if (full) {
          free_entry = entry;
          full = false;
        }
      }
  }

  if (full) {
    /* If the cache is full we must evict the LRU entry. */
    entry = list_entry(e = list_pop_back(&buffer_cache), struct buffer_cache_entry, elem);

    /* Check if dirty. */
    if (entry->dirty) {
      /* Release global lock so we don't block */
      lock_release(&buffer_cache_lock);
      lock_acquire(&entry->entry_lock);
  
      block_write(fs_device, entry->sector, entry->contents);

      lock_release(&entry->entry_lock);
      lock_acquire(&buffer_cache_lock);
    }
  } else {
    entry = free_entry;
    list_remove(&entry->elem);
  }

  /* Read in sector from disk */
  if (offset > 0 || size < BLOCK_SECTOR_SIZE) {
    /* Release global lock so we don't block */
    lock_release(&buffer_cache_lock);
    lock_acquire(&entry->entry_lock);
    
    block_read(fs_device, sector, entry->contents);

    lock_release(&entry->entry_lock);
    lock_acquire(&buffer_cache_lock);

  } else {
    memset(entry->contents, 0, BLOCK_SECTOR_SIZE);
  }
  entry->sector = sector;
  entry->dirty = false;
  entry->in_use = true;
  memcpy(entry->contents + offset, buffer, size);

  /* Release global lock so we don't block */
  lock_release(&buffer_cache_lock);
  lock_acquire(&entry->entry_lock);

  block_write(fs_device, entry->sector, entry->contents);

  lock_release(&entry->entry_lock);
  lock_acquire(&buffer_cache_lock);
  
  list_push_front(&buffer_cache, &entry->elem);
  
  lock_release(&buffer_cache_lock);
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
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->is_dir = is_dir;
    if (inode_resize(disk_inode, sector, length)) {
      // block_write(fs_device, sector, disk_inode);
      cache_write(fs_device, sector, disk_inode, BLOCK_SECTOR_SIZE, 0);
      success = true;
    }
    free(disk_inode);
  }
  return success;
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

  struct inode_disk* id = get_disk_inode(inode);
  inode->is_dir = id->is_dir;
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
    lock_acquire(&inode_list_lock);
    list_remove(&inode->elem);
    lock_release(&inode_list_lock);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      struct inode_disk* id = get_disk_inode(inode);
      ASSERT(id != NULL);
      
      inode_resize(id, inode->sector, 0);
      free_map_release(inode->sector, 1);
    }
    lock_release(&inode->inode_lock);
    free(inode);
  } else {
    lock_release(&inode->inode_lock);
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
  uint8_t* contents = NULL;

  lock_acquire(&inode->inode_lock);
  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    contents = (uint8_t*) cache_read(fs_device, sector_idx);
    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Copy full sector from cache into user buffer */
      memcpy(buffer + bytes_read, contents, BLOCK_SECTOR_SIZE);
    } else {
      /* Partially copy contents from cache into user buffer */
      memcpy(buffer + bytes_read, contents + sector_ofs, chunk_size);
    }


    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  lock_release(&inode->inode_lock);

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
  
  lock_acquire(&inode->inode_lock);
  if (inode->deny_write_cnt) {
    lock_release(&inode->inode_lock);
    return 0;
  }

  if (offset + size > inode_length(inode)) {
    struct inode_disk* id = get_disk_inode(inode);
    if (!inode_resize(id, inode->sector, offset + size)) {
      lock_release(&inode->inode_lock);
      return 0;
    }
    cache_write(fs_device, inode->sector, id, BLOCK_SECTOR_SIZE, 0);
  }
  
  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    cache_write(fs_device, sector_idx, buffer + bytes_written, chunk_size, sector_ofs);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  lock_release(&inode->inode_lock);

  return bytes_written;
}

bool inode_resize(struct inode_disk* id, block_sector_t inode_sector, off_t size) {
  static char zeros[BLOCK_SECTOR_SIZE];
  bool indirect_allocated = false;
  bool double_indirect_allocated = false;

  /* If allocation fails we must reset the disk to how it was before */
  bool reset = false;

  /* Handle direct pointers. */
  for (int i = 0; i < INODE_DIRECT; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && id->direct_ptrs[i] != 0) {
      /* Shrink. */
      free_map_release(id->direct_ptrs[i], 1);
      id->direct_ptrs[i] = 0;
      
      /* Update inode */
      cache_write(fs_device, inode_sector, id, BLOCK_SECTOR_SIZE, 0);
    } else if (size > BLOCK_SECTOR_SIZE * i && id->direct_ptrs[i] == 0) {
      /* Grow. */
      if(!free_map_allocate(1, &id->direct_ptrs[i])) {
        reset = true;
        goto done;
      }
      cache_write(fs_device, id->direct_ptrs[i], zeros, BLOCK_SECTOR_SIZE, 0);
      
      /* Update inode*/
      cache_write(fs_device, inode_sector, id, BLOCK_SECTOR_SIZE, 0);
    }
  }


  /* Check if indirect pointers are needed. */
  if (id->single_indirect_ptr == 0 && size <= INODE_DIRECT * BLOCK_SECTOR_SIZE) {
    goto done;
  }

  block_sector_t* indirect_block;
  if (id->single_indirect_ptr == 0) {
    /* Allocate indirect block. */
    indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
    if (!free_map_allocate(1, &id->single_indirect_ptr) || indirect_block == NULL) {
      reset = true;
      goto done;
    }
    /* Update inode */
    cache_write(fs_device, inode_sector, id, BLOCK_SECTOR_SIZE, 0);
    indirect_allocated = true;
  } else {
    /* Read in indirect block. */
    indirect_block = (block_sector_t*)cache_read(fs_device, id->single_indirect_ptr);
  }
  
  /* Handle indirect pointers. */
  for (int i = 0; i < BLOCK_POINTERS_PER_SECTOR; i++) {
    if (size <= (INODE_DIRECT + i) * BLOCK_SECTOR_SIZE && indirect_block[i] != 0) {
      /* Shrink. */
      free_map_release(indirect_block[i], 1);
      indirect_block[i] = 0;
      /* Update indirect block */
      cache_write(fs_device, id->single_indirect_ptr, indirect_block, BLOCK_SECTOR_SIZE, 0);
    } else if (size > (INODE_DIRECT + i) * BLOCK_SECTOR_SIZE && indirect_block[i] == 0) {
      /* Grow. */
      if (!free_map_allocate(1, &indirect_block[i])) {
        reset = true;
        goto done;
      }
      cache_write(fs_device, indirect_block[i], zeros, BLOCK_SECTOR_SIZE, 0);
      /* Update indirect block */
      cache_write(fs_device, id->single_indirect_ptr, indirect_block, BLOCK_SECTOR_SIZE, 0);
    }
  }

  /* Write the updates to the indirect block back to disk. */
  if (size <= INODE_DIRECT * BLOCK_SECTOR_SIZE) {
    /* We shrank the inode such that indirect pointers are not required. */
    free_map_release(id->single_indirect_ptr, 1);
    id->single_indirect_ptr = 0;
    /* Update inode */
    cache_write(fs_device, inode_sector, id, BLOCK_SECTOR_SIZE, 0);
  }

  /* Handle double indirect block */
  if (size <= (INODE_DIRECT + BLOCK_POINTERS_PER_SECTOR) * BLOCK_SECTOR_SIZE && id->double_indirect_ptr == 0) {
    goto done;
  }

  block_sector_t* double_indirect_block;
  if (id->double_indirect_ptr == 0) {
    /* Allocate double indirect block. */
    double_indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
    if (!free_map_allocate(1, &id->double_indirect_ptr) || double_indirect_block == NULL) {
      reset = true;
      goto done;
    }
    /* Update inode */
    cache_write(fs_device, inode_sector, id, BLOCK_SECTOR_SIZE, 0);
    double_indirect_allocated = true;
  } else {
    /* Read in double indirect block. */
    double_indirect_block = (block_sector_t*)cache_read(fs_device, id->double_indirect_ptr);
  }

  for (int i = 0; i < BLOCK_POINTERS_PER_SECTOR; i++) {
    /* Check if any more indirect pointers in the double indirect block are needed. */
    if (size <= (INODE_DIRECT + BLOCK_POINTERS_PER_SECTOR + (BLOCK_POINTERS_PER_SECTOR * i)) * BLOCK_SECTOR_SIZE && double_indirect_block[i] == 0) {
      break;
    }

    if (double_indirect_block[i] == 0) {
      /* Allocate indirect block. */
      if (indirect_allocated) {
        memset(indirect_block, 0, BLOCK_SECTOR_SIZE);
      }
      else {
        indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
        indirect_allocated = true;
      }
      if (!free_map_allocate(1, &double_indirect_block[i]) || indirect_block == NULL) {
        reset = true;
        goto done;
      }
      /* Update double indirect block*/
      cache_write(fs_device, id->double_indirect_ptr, double_indirect_block, BLOCK_SECTOR_SIZE, 0);
    } else {
      indirect_block = cache_read(fs_device, double_indirect_block[i]);
    }

    /* Handle indirect pointers */
    for (int j = 0; j < BLOCK_POINTERS_PER_SECTOR; j++) {
      if (size <= (INODE_DIRECT + BLOCK_POINTERS_PER_SECTOR + (BLOCK_POINTERS_PER_SECTOR * i) + j) * BLOCK_SECTOR_SIZE && indirect_block[j] != 0) {
        /* Shrink */
        free_map_release(indirect_block[j], 1);
        indirect_block[j] = 0;
        /* Update indirect block */
        cache_write(fs_device, double_indirect_block[i], indirect_block, BLOCK_SECTOR_SIZE, 0);
      } else if (size > (INODE_DIRECT + BLOCK_POINTERS_PER_SECTOR + (BLOCK_POINTERS_PER_SECTOR * i) + j) * BLOCK_SECTOR_SIZE && indirect_block[j] == 0) {
        /* Grow */
        if (!free_map_allocate(1, &indirect_block[j])) {
          reset = true;
          goto done;
        }
        cache_write(fs_device, indirect_block[j], zeros, BLOCK_SECTOR_SIZE, 0);
        /* Update indirect block */
        cache_write(fs_device, double_indirect_block[i], indirect_block, BLOCK_SECTOR_SIZE, 0);
      }
    }

    if (size <= (INODE_DIRECT + BLOCK_POINTERS_PER_SECTOR + (BLOCK_POINTERS_PER_SECTOR * i)) * BLOCK_SECTOR_SIZE) {
      /* We shrank the inode such that this indirect block is not required are not required */
      free_map_release(double_indirect_block[i], 1);
      double_indirect_block[i] = 0;
      
      /* Update double indirect block*/
      cache_write(fs_device, id->double_indirect_ptr, double_indirect_block, BLOCK_SECTOR_SIZE, 0);
    }
  }

  /* Write updates to double indirect block to disk */
  if (size <= (INODE_DIRECT + BLOCK_POINTERS_PER_SECTOR) * BLOCK_SECTOR_SIZE) {
    /* We shrank the inode such that double indirect pointers are not required */
    free_map_release(id->double_indirect_ptr, 1);
    id->double_indirect_ptr = 0;

    /* Update inode */
    cache_write(fs_device, inode_sector, id, BLOCK_SECTOR_SIZE, 0);
  }

done:
  if (indirect_allocated)
    free(indirect_block);
  if (double_indirect_allocated)
    free(double_indirect_block);
  if (reset) {
    inode_resize(id, inode_sector, id->length);
    return false;
  }
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
  struct inode_disk* id = get_disk_inode(inode);
  return id->length;
}

int get_cache_hits(void) {
  return num_hits;
}