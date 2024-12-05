#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include "lab.h"

// Helper macros for calculating block size and offsets
#define BLOCK_SIZE(k) (1 << (k))
#define BLOCK_OFFSET(pool, block) ((void *)(block) - (pool)->base)

/**
 * Converts bytes to the nearest power of 2 (2^K).
 * @param bytes The size in bytes.
 * @return The power K where 2^K >= bytes.
 */
size_t btok(size_t bytes)
{
    size_t count = 0;
    bytes--;
    while (bytes > 0)
    {
        bytes >>= 1;
        count++;
    }
    return count;
}

/**
 * Calculates the buddy of a given block.
 * @param pool The memory pool.
 * @param block The block whose buddy is to be found.
 * @return Pointer to the buddy block.
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block)
{
    size_t offset = BLOCK_OFFSET(pool, block);
    size_t block_size = BLOCK_SIZE(block->kval);
    void *buddy_addr = (void *)(pool->base + (offset ^ block_size));
    return (struct avail *)buddy_addr;
}

/**
 * Splits a block into two buddies and adds one to the free list.
 */
void split_block(struct buddy_pool *pool, struct avail *block)
{
    block->kval--;
    struct avail *buddy = buddy_calc(pool, block);

    buddy->kval = block->kval;
    buddy->tag = BLOCK_AVAIL;

    buddy->next = pool->avail[buddy->kval].next;
    buddy->prev = &pool->avail[buddy->kval];
    pool->avail[buddy->kval].next->prev = buddy;
    pool->avail[buddy->kval].next = buddy;
}

/**
 * Allocates memory from the buddy pool.
 */
void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    if (!size || !pool)
        return NULL;

    size_t k = btok(size + sizeof(struct avail));
    if (k > pool->kval_m)
        return NULL;

    for (size_t i = k; i <= pool->kval_m; i++)
    {
        struct avail *block = pool->avail[i].next;
        if (block->tag == BLOCK_AVAIL && block != &pool->avail[i])
        {
            block->prev->next = block->next;
            block->next->prev = block->prev;

            block->tag = BLOCK_RESERVED;

            while (block->kval > k)
                split_block(pool, block);

            return (void *)((char *)block + sizeof(struct avail));
        }
    }

    errno = ENOMEM;
    return NULL;
}

/**
 * Frees memory back to the buddy pool.
 */
void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (!ptr || !pool)
        return;

    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
    block->tag = BLOCK_AVAIL;

    while (block->kval < pool->kval_m)
    {
        struct avail *buddy = buddy_calc(pool, block);
        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval)
            break;

        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        if ((void *)buddy < (void *)block)
            block = buddy;

        block->kval++;
    }

    block->next = &pool->avail[block->kval];
    block->prev = &pool->avail[block->kval];
    pool->avail[block->kval].next = block;
    pool->avail[block->kval].prev = block;
}

/**
 * Reallocates memory in the buddy pool.
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    if (!ptr)
        return buddy_malloc(pool, size);

    if (!size)
    {
        buddy_free(pool, ptr);
        return NULL;
    }

    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
    size_t current_size = BLOCK_SIZE(block->kval);

    if (size + sizeof(struct avail) <= current_size)
        return ptr;

    void *new_ptr = buddy_malloc(pool, size);
    if (new_ptr)
    {
        memcpy(new_ptr, ptr, current_size - sizeof(struct avail));
        buddy_free(pool, ptr);
    }

    return new_ptr;
}

/**
 * Initializes a new buddy memory pool.
 */
void buddy_init(struct buddy_pool *pool, size_t size)
{
    if (!size)
        size = UINT64_C(1) << DEFAULT_K;

    pool->kval_m = btok(size);
    pool->numbytes = BLOCK_SIZE(pool->kval_m);

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->base == MAP_FAILED)
    {
        perror("buddy: could not allocate memory pool!");
        return;
    }

    for (size_t i = 0; i <= pool->kval_m; i++)
    {
        pool->avail[i].next = &pool->avail[i];
        pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    struct avail *initial_block = (struct avail *)pool->base;
    initial_block->kval = pool->kval_m;
    initial_block->tag = BLOCK_AVAIL;
    initial_block->next = initial_block->prev = &pool->avail[pool->kval_m];
    pool->avail[pool->kval_m].next = pool->avail[pool->kval_m].prev = initial_block;
}

/**
 * Destroys a buddy memory pool.
 */
void buddy_destroy(struct buddy_pool *pool)
{
    if (munmap(pool->base, pool->numbytes) == -1)
        perror("buddy: destroy failed!");
}
