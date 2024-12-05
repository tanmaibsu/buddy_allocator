#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include "lab.h"

/**
 * Converts bytes to its equivalent K value defined as bytes <= 2^K
 * @param bytes The bytes needed
 * @return K The number of bytes expressed as 2^K
 */
size_t btok(size_t bytes)
{
  unsigned int count = 0;
  bytes--;
  while (bytes > 0)
  {
    bytes >>= 1;
    count++;
  }
  return count;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
  size_t offset = (void *)buddy - pool->base; // Offset of the block from the base
  size_t block_size = 1 << buddy->kval;       // Size of the block (2^kval)

  // XOR with block size to calculate buddy address
  void *buddy_addr = (void *)(pool->base + (offset ^ block_size));
  return (struct avail *)buddy_addr;
}

void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
  if (size == 0 || pool == NULL)
  {
    return NULL; // Invalid request
  }

  size_t k = btok(size + sizeof(struct avail)); // Include header in allocation
  if (k > pool->kval_m)
  {
    return NULL; // Requested size is too large
  }

  // Find the smallest block size that can fit
  for (size_t i = k; i <= pool->kval_m; i++)
  {
    struct avail *block = pool->avail[i].next;
    if (block->tag == BLOCK_AVAIL && block != &pool->avail[i])
    {
      // Remove block from the free list
      block->next->prev = block->prev;
      block->prev->next = block->next;

      block->tag = BLOCK_RESERVED;

      // Split blocks if necessary
      while (block->kval > k)
      {
        block->kval--;
        struct avail *buddy = buddy_calc(pool, block);
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = block->kval;

        // Add buddy to free list
        buddy->next = pool->avail[buddy->kval].next;
        buddy->prev = &pool->avail[buddy->kval];
        pool->avail[buddy->kval].next->prev = buddy;
        pool->avail[buddy->kval].next = buddy;
      }

      return (void *)((char *)block + sizeof(struct avail));
    }
  }

  errno = ENOMEM; // No suitable block found
  return NULL;
}

void buddy_free(struct buddy_pool *pool, void *ptr)
{
  if (ptr == NULL || pool == NULL)
  {
    return;
  }

  // Get the block header
  struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));

  block->tag = BLOCK_AVAIL;

  // Try to merge with buddy
  while (block->kval < pool->kval_m)
  {
    struct avail *buddy = buddy_calc(pool, block);
    if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval)
    {
      break; // Buddy is not free or is not of the same size
    }

    // Remove buddy from the free list
    buddy->prev->next = buddy->next;
    buddy->next->prev = buddy->prev;

    // Merge blocks
    if ((void *)buddy < (void *)block)
    {
      block = buddy;
    }
    block->kval++;
  }

  // Add block to the free list
  block->next = &pool->avail[block->kval];
  block->prev = &pool->avail[block->kval];
  pool->avail[block->kval].next = block;
  pool->avail[block->kval].prev = block;
}

void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
  if (ptr == NULL)
  {
    return buddy_malloc(pool, size); // Behaves like malloc
  }

  if (size == 0)
  {
    buddy_free(pool, ptr); // Behaves like free
    return NULL;
  }

  // Get the block header
  struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
  size_t current_size = 1 << block->kval;

  if (size + sizeof(struct avail) <= current_size)
  {
    return ptr; // Existing block is sufficient
  }

  // Allocate a new block
  void *new_ptr = buddy_malloc(pool, size);
  if (new_ptr)
  {
    // Copy existing data to new block
    memcpy(new_ptr, ptr, current_size - sizeof(struct avail));
    buddy_free(pool, ptr);
  }

  return new_ptr;
}

/**
 * Initialize a new memory pool using the buddy algorithm. Internally,
 * this function uses mmap to get a block of memory to manage so should be
 * portable to any system that implements mmap. This function will round
 * up to the nearest power of two. So if the user requests 503MiB
 * it will be rounded up to 512MiB.
 *
 * Note that if a 0 is passed as an argument then it initializes
 * the memory pool to be of the default size of DEFAULT_K. If the caller
 * specifies an unreasonably small size, then the buddy system may
 * not be able to satisfy any requests.
 *
 * NOTE: Memory pools returned by this function can not be intermingled.
 * Calling buddy_malloc with pool A and then calling buddy_free with
 * pool B will result in undefined behavior.
 *
 * @param size The size of the pool in bytes.
 * @param pool A pointer to the pool to initialize
 */
void buddy_init(struct buddy_pool *pool, size_t size)
{
  if (size == 0)
  {
    size = UINT64_C(1) << DEFAULT_K;
  }
  pool->kval_m = btok(size);
  pool->numbytes = UINT64_C(1) << pool->kval_m;

  pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (pool->base == MAP_FAILED)
  {
    perror("buddy: could not allocate memory pool!");
  }

  for (size_t i = 0; i < pool->kval_m; i++)
  {
    pool->avail[i].next = &pool->avail[i];
    pool->avail[i].prev = &pool->avail[i];
    pool->avail[i].kval = i;
    pool->avail[i].tag = BLOCK_UNUSED;
  }
  pool->avail[pool->kval_m].next = pool->base;
  pool->avail[pool->kval_m].prev = pool->base;

  struct avail *ptr = (struct avail *)pool->base;
  ptr->tag = BLOCK_AVAIL;
  ptr->kval = pool->kval_m;
  ptr->next = &pool->avail[pool->kval_m];
  ptr->prev = &pool->avail[pool->kval_m];
}

/**
 * Inverse of buddy_init.
 *
 * Notice that this function does not change the value of pool itself,
 * hence it still points to the same (now invalid) location.
 *
 * @param pool The memory pool to destroy
 */
void buddy_destroy(struct buddy_pool *pool)
{

  int status = munmap(pool->base, pool->numbytes);
  if (status == -1)
  {
    perror("buddy: destroy failed!");
  }
}