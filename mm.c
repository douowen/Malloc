#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "./memlib.h"
#include "./mm.h"
#include "./mminline.h"

#define MAX(a, b) (a > b ? a : b)

block_t *prologue;
block_t *epilogue;
// rounds up to the nearest multiple of WORD_SIZE
static inline size_t align(size_t size) {
    return (((size) + (WORD_SIZE - 1)) & ~(WORD_SIZE - 1));
}

int mm_check_heap(void);

/*
 *                             _       _ _
 *     _ __ ___  _ __ ___     (_)_ __ (_) |_
 *    | '_ ` _ \| '_ ` _ \    | | '_ \| | __|
 *    | | | | | | | | | | |   | | | | | | |_
 *    |_| |_| |_|_| |_| |_|___|_|_| |_|_|\__|
 *                       |_____|
 *
 * initializes the dynamic storage allocator (allocate initial heap space)
 * arguments: none
 * returns: 0, if successful
 *         -1, if an error occurs
 */
int mm_init(void) {
    // Allocate memories to prologue and epilogue with 16 bytes to each.
    if ((prologue = (block_t *)mem_sbrk(TAGS_SIZE)) == (void *)-1) {
        return -1;
    }
    block_set_size_and_allocated(prologue, TAGS_SIZE, 1);
    if ((epilogue = (block_t *)mem_sbrk(TAGS_SIZE)) == (void *)-1) {
        return -1;
    }
    block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);

    // Initiate the flist_first
    flist_first = NULL;
    return 0;
}

/*     _ __ ___  _ __ ___      _ __ ___   __ _| | | ___   ___
 *    | '_ ` _ \| '_ ` _ \    | '_ ` _ \ / _` | | |/ _ \ / __|
 *    | | | | | | | | | | |   | | | | | | (_| | | | (_) | (__
 *    |_| |_| |_|_| |_| |_|___|_| |_| |_|\__,_|_|_|\___/ \___|
 *                       |_____|
 *
 * allocates a block of memory and returns a pointer to that block's payload
 * arguments: size: the desired payload size for the block
 * returns: a pointer to the newly-allocated block's payload (whose size
 *          is a multiple of ALIGNMENT), or NULL if an error occurred
 */
void *mm_malloc(size_t size) {
    // TODO
    if ((int)size <= 0) {
        return NULL;
    }

    if (size < MINBLOCKSIZE) {
        size = MINBLOCKSIZE;
    }

    size = align(size);
    block_t *head = flist_first;
    block_t *current = flist_first;
    size_t more_space = 512;
    size_t size_after_extended =
        MAX(size + TAGS_SIZE, more_space);  // Reduce calls to extend heap.

    // Extend the heap when by size_after_extended size when there's no free
    // blocks
    if (current == NULL) {
        block_t *temp;
        if ((temp = (block_t *)mem_sbrk(align(size_after_extended))) ==
            (void *)-1) {
            perror("Error: cannot extend the heap.");
            return NULL;
        }

        // Adjust the epilogue's position
        temp = epilogue;
        block_set_size_and_allocated(temp, size_after_extended, 0);
        insert_free_block(temp);
        epilogue = block_next(temp);
        block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);
        if ((current = temp) == (void *)-1) {
            perror("Extend heap failure\n");
            return NULL;
        }
    } else {
        // Traverse the heap until it finds a free block that fits.
        while (block_size(current) < size + TAGS_SIZE) {
            current = block_next_free(current);
            // If it doesn't find an free block that has the sufficient size,
            // extend the heap by size_after_extended size
            if (current == head) {
                block_t *temp;
                if ((temp = (block_t *)mem_sbrk(align(size_after_extended))) ==
                    (void *)-1) {
                    perror("Error: cannot extend the heap.");
                    return NULL;
                }
                temp = epilogue;
                block_set_size_and_allocated(temp, size_after_extended, 0);
                insert_free_block(temp);
                epilogue = block_next(temp);
                block_set_size_and_allocated(epilogue, TAGS_SIZE, 1);
                if ((current = temp) == (void *)-1) {
                    perror("Extend heap failure\n");
                    return NULL;
                }
            }
        }
    }

    // Split the original block if its greater than the passed size by
    // minblocksize.
    if (block_size(current) - size - TAGS_SIZE >= MINBLOCKSIZE) {
        size_t original_block_size = block_size(current);
        pull_free_block(current);
        block_set_size_and_allocated(current, size + TAGS_SIZE, 1);
        block_t *extend_block = block_next(current);
        block_set_size_and_allocated(extend_block,
                                     original_block_size - size - TAGS_SIZE, 0);
        insert_free_block(extend_block);
    } else {
        // Otherwise pull out the block from the flist and set it allocated
        pull_free_block(current);
        block_set_allocated(current, 1);
    }

    return current->payload;
}

/*                              __
 *     _ __ ___  _ __ ___      / _|_ __ ___  ___
 *    | '_ ` _ \| '_ ` _ \    | |_| '__/ _ \/ _ \
 *    | | | | | | | | | | |   |  _| | |  __/  __/
 *    |_| |_| |_|_| |_| |_|___|_| |_|  \___|\___|
 *                       |_____|
 *
 * frees a block of memory, enabling it to be reused later
 * arguments: ptr: pointer to the block's payload
 * returns: nothing
 */
void mm_free(void *ptr) {
    // TODO
    if (ptr != NULL) {
        block_t *block = payload_to_block(ptr);
        assert(block_allocated(block));
        block_set_allocated(block, 0);
        insert_free_block(block);
        // Check the previous and the next neighbor block and coalesce the free
        // blocks
        block_t *prev = block_prev(block);
        block_t *next = block_next(block);
        pull_free_block(block);
        // Coalesce the passed free block with the previous neighbor free block
        if (!block_allocated(prev)) {
            pull_free_block(prev);
            block_set_size(prev, block_size(block) + block_size(prev));
            block = prev;
        }

        // coalesce the passed free block with the next neighbor free block
        if (!block_allocated(next)) {
            pull_free_block(next);
            block_set_size(block, block_size(block) + block_size(next));
        }

        insert_free_block(
            block);  // Adding the coalesced free block back to the free list.
    }
}

/*
 *                                            _ _
 *     _ __ ___  _ __ ___      _ __ ___  __ _| | | ___   ___
 *    | '_ ` _ \| '_ ` _ \    | '__/ _ \/ _` | | |/ _ \ / __|
 *    | | | | | | | | | | |   | | |  __/ (_| | | | (_) | (__
 *    |_| |_| |_|_| |_| |_|___|_|  \___|\__,_|_|_|\___/ \___|
 *                       |_____|
 *
 * reallocates a memory block to update it with a new given size
 * arguments: ptr: a pointer to the memory block's payload
 *            size: the desired new payload size
 * returns: a pointer to the new memory block's payload
 */
void *mm_realloc(void *ptr, size_t size) {
    // TODO
    if (ptr == NULL) {
        if (size > 0) {
            mm_malloc(size);
            return NULL;
        }
    }

    if ((int)size < 0) {
        return NULL;
    } else if (size == 0 && ptr != NULL) {
        mm_free(ptr);
        return NULL;
    }

    size = align(size) + TAGS_SIZE;
    block_t *block = payload_to_block(ptr);
    size_t original_size = block_size(block);

    // Reallocating to a smaller size, simply return the original pointer to
    // preserve the data.
    if (original_size >= size) {
        return block->payload;
    } else {
        // check if the next neighbor block is free and coalesce them if it is.
        block_t *next_free = block_next(block);
        size_t new_size = original_size - TAGS_SIZE;
        if (!block_allocated(next_free)) {
            pull_free_block(next_free);
            block_set_size_and_allocated(
                block, block_size(block) + block_size(next_free), 1);
            original_size = block_size(block);
            if (original_size >= size) {
                return block->payload;
            }
        }

        // Check if the previous neighbor block is free and coalesce them if it
        // is.
        if (original_size < size) {
            block_t *prev_free = block_prev(block);
            if (!block_allocated(prev_free)) {
                pull_free_block(prev_free);
                block_set_size_and_allocated(
                    prev_free, block_size(block) + block_size(prev_free), 1);
                block = prev_free;
                original_size = block_size(block);
                if (original_size >= size) {
                    memmove(block->payload, ptr, new_size);
                    return block->payload;
                }
                ptr = block->payload;
            }
        }

        block_t *extend_payload;
        if ((extend_payload = mm_malloc(size)) == NULL) {
            perror("Error: failed to malloc the payload.");
            return NULL;
        }

        block_t *extend_block = payload_to_block(extend_payload);
        memcpy(extend_block->payload, ptr, new_size);
        mm_free(ptr);  // Free the old block
        return extend_block->payload;
    }
    return block->payload;
}

/*
 * checks the state of the heap for internal consistency and prints informative
 * error messages
 * arguments: none
 * returns: 0, if successful
 *          nonzero, if the heap is not consistent
 */
int mm_check_heap(void) {
    // TODO
    if (flist_first == NULL) {
        return 0;
    }

    block_t *current = flist_first;
    if (block_allocated(current)) {
        printf("Block address: %p\n", (void *)current);
        printf("Block size: %ld\n", block_size(current));
        printf("Heap error: %s\n", "An allocated block is in the flist.");
        exit(1);
    }

    current = block_next_free(current);
    while (current != flist_first) {
        // Check if all blocks in flist are free or not.
        if (block_allocated(current)) {
            printf("Block address: %p\n", (void *)current);
            printf("Block size: %ld\n", block_size(current));
            printf("Heap error: %s\n", "an allocated block is in the flist.");
            exit(1);
        }

        // Check if the preveious free block neighbor is actually free
        if (block_allocated(block_prev_free(current))) {
            printf("Block address: %p\n", (void *)current);
            printf("Block size: %ld\n", block_size(current));
            printf("Heap error: %s\n",
                   "the previous neighbor block in the flist is allocated.");
            exit(1);
        }

        // Check if the next free block neighbor is actually free
        if (block_allocated(block_next_free(current))) {
            printf("Block address: %p\n", (void *)current);
            printf("Block size: %ld\n", block_size(current));
            printf("Heap error: %s\n",
                   "the next neighbor block in the flist is allocated.");
            exit(1);
        }

        // Check if the previous block is free and haven't been coalesced
        if (!block_allocated(block_prev(current))) {
            printf("Block address: %p\n", (void *)current);
            printf("Block size: %ld\n", block_size(current));
            printf("Heap error: %s\n",
                   "the previous neighbor block in the flist has not been "
                   "coalesced.");
            exit(1);
        }

        // Check if the next block is free and haven't been coalesced
        if (!block_allocated(block_next(current))) {
            printf("Block address: %p\n", (void *)current);
            printf("Block size: %ld\n", block_size(current));
            printf(
                "Heap error: %s\n",
                "the next neighbor block in the flist has not been coalesced.");
            exit(1);
        }

        current = block_next_free(current);
    }

    block_t *heap_lo = mem_heap_lo();
    block_t *heap_hi = mem_heap_hi();
    // Check if the prologue is the first block in the heap.
    if ((current = heap_lo) != prologue) {
        printf("Block address: %p\n", (void *)current);
        printf("Block size: %ld\n", block_size(current));
        printf("Heap error: %s\n",
               "prologue is not the first block in the heap.");
        exit(1);
    }

    // Check if the epilogue is the last block in the heap.
    if ((void *)((long)heap_hi - (long)(TAGS_SIZE - 1)) != epilogue) {
        printf("Block address: %p\n", (void *)current);
        printf("Block size: %ld\n", block_size(current));
        printf("Heap error: %s\n",
               "epilogue is not the last block in the heap.");
        exit(1);
    }

    // Check if all blocks are in bounds
    while (current != epilogue) {
        if (current < heap_lo || current > heap_hi) {
            printf("Block address: %p\n", (void *)current);
            printf("Block size: %ld\n", block_size(current));
            printf("Heap error: %s\n", "this block is out of bound.");
            exit(1);
        }

        // Check if the header and the footers are matched.
        if (block_size(current) != block_end_size(current) ||
            block_allocated(current) != block_end_allocated(current)) {
            printf("Block address: %p\n", (void *)current);
            printf("Block size: %ld\n", block_size(current));
            printf("Heap error: %s\n", "header and footers do not match.");
            exit(1);
        }

        current = block_next(current);
    }

    if (epilogue < heap_lo || epilogue > heap_hi) {
        printf("Block address: %p\n", (void *)current);
        printf("Block size: %ld\n", block_size(current));
        printf("Heap error: %s\n", "this block is out of bound.");
        exit(1);
    }

    return 0;
}
