#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>

#define PAGE_SIZE (4096 * 1024)
#define ALIGNMENT 8
//given  MIN_BLOCK_SIZE = 3 * ALIGNMENT

void *mem_head = NULL;

void *memalloc(unsigned long allocation_size) 
{
    if (allocation_size <= 0) return NULL;

    // Ensuring proper memory alignment
    if (allocation_size % ALIGNMENT != 0) 
        allocation_size += (ALIGNMENT - allocation_size % ALIGNMENT);
    if (allocation_size < 2 * ALIGNMENT) allocation_size = 2 * ALIGNMENT;

    if (mem_head == NULL) {
        // Initialize the memory pool if it doesn't exist
        mem_head = mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem_head == MAP_FAILED) {
            perror("mmap");
            return NULL;
        }
        *(unsigned long *)mem_head = PAGE_SIZE;
        *(void **)(mem_head + ALIGNMENT) = NULL;
        *(void **)(mem_head + 2 * ALIGNMENT) = NULL;
    }
    
    void* temp_block = mem_head;
    while (temp_block != NULL && *(unsigned long *)temp_block < allocation_size + ALIGNMENT) {
        temp_block = *(void **)(temp_block + ALIGNMENT);
    }
    
    if (temp_block == NULL) {
        // Allocate a new block if there's not enough space in the free list
        unsigned long num_pages;
        if ((allocation_size + ALIGNMENT) % PAGE_SIZE != 0)
            num_pages = (allocation_size + ALIGNMENT) / PAGE_SIZE + 1;
        else
            num_pages = (allocation_size + ALIGNMENT) / PAGE_SIZE;
        
        void* allocated_block = mmap(NULL, num_pages * PAGE_SIZE, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (allocated_block == MAP_FAILED) {
            perror("mmap");
            return NULL;
        }
        *(unsigned long *)allocated_block = allocation_size + ALIGNMENT;
        void* new_block = allocated_block + allocation_size + ALIGNMENT;
        
        if (num_pages * PAGE_SIZE - (allocation_size + ALIGNMENT) < 3 * ALIGNMENT) {
            // If remaining space is too small, use the entire block
            *(unsigned long *)allocated_block = num_pages * PAGE_SIZE;
            return (void *)(allocated_block + ALIGNMENT);
        }
        
        if (new_block != NULL) {
            // Split the remaining space into a new block
            *(unsigned long *)new_block = num_pages * PAGE_SIZE - (allocation_size + ALIGNMENT);
            *(void **)(mem_head + 2 * ALIGNMENT) = new_block;
            *(void **)(new_block + ALIGNMENT) = mem_head;
            *(void **)(new_block + 2 * ALIGNMENT) = NULL;
            mem_head = new_block;
        }
        return (void *)(allocated_block + ALIGNMENT);
    } else {
        // Use an existing block
        void* prev_block = *(void **)(temp_block + 2 * ALIGNMENT);
        void* next_block = *(void **)(temp_block + ALIGNMENT);
        
        if (*(unsigned long *)temp_block >= allocation_size + 2 * ALIGNMENT) {
            // If the block is large enough, split it
            void* new_block = (void *)(temp_block + allocation_size + ALIGNMENT);
            *(unsigned long *)new_block = *(int *)temp_block - (allocation_size + ALIGNMENT);
            *(unsigned long *)temp_block = allocation_size + ALIGNMENT;
            
            if (prev_block != NULL) {
                *(void **)(prev_block + ALIGNMENT) = next_block;
                *(void **)(next_block + 2 * ALIGNMENT) = prev_block;
                *(void **)(new_block + ALIGNMENT) = mem_head;
                *(void **)(new_block + 2 * ALIGNMENT) = NULL;
                mem_head = new_block;
            } else {
                mem_head = new_block;
                *(void **)(new_block + 2 * ALIGNMENT) = NULL;
                *(void **)(new_block + ALIGNMENT) = next_block;
            }
            return (void *)(temp_block + ALIGNMENT);
        } else {
            // Reuse the entire block
            if (prev_block != NULL) {
                *(void **)(prev_block + ALIGNMENT) = next_block;
                if (next_block != NULL)
                    *(void **)(next_block + 2 * ALIGNMENT) = prev_block;
            } else {
                mem_head = next_block;
                *(void **)(next_block + 2 * ALIGNMENT) = NULL;
            }
            return (void *)(temp_block + ALIGNMENT);
        }
    }
    return NULL;
}

int memfree(void *ptr)
{
    if (ptr == NULL) return -1;
    ptr = ptr - ALIGNMENT;
    void* temp_left = mem_head;
    
    // Find the left adjacent block
    while (temp_left != NULL && (temp_left + *(unsigned long *)(temp_left)) != ptr) {
        temp_left = *(void **)(temp_left + ALIGNMENT);
    }
    
    void* temp_right = mem_head;
    
    // Find the right adjacent block
    while (temp_right != NULL && (ptr + *(unsigned long *)(ptr)) != temp_right) {
        temp_right = *(void **)(temp_right + ALIGNMENT);
    }
    
    if (temp_left != NULL) {
        // Merge with the left adjacent block
        void* left_block = *(void **)(temp_left + 2 * ALIGNMENT);
        void* right_block = *(void **)(temp_left + ALIGNMENT);
        *(unsigned long *)(temp_left) += (*(unsigned long *)(ptr));
        ptr = temp_left;
        
        if (left_block != NULL) {
            *(void **)(left_block + ALIGNMENT) = right_block;
        } else if (right_block != NULL) {
            mem_head = right_block;
        }
        
        if (right_block != NULL) {
            *(void **)(right_block + 2 * ALIGNMENT) = left_block;
        }
    }
    
    if (temp_right != NULL) {
        // Merge with the right adjacent block
        void* left_block = *(void **)(temp_right + 2 * ALIGNMENT);
        void* right_block = *(void **)(temp_right + ALIGNMENT);
        *(unsigned long *)(ptr) += (*(unsigned long *)(temp_right));
        
        if (left_block != NULL) {
            *(void **)(left_block + ALIGNMENT) = right_block;
        } else if (right_block != NULL) {
            mem_head = right_block;
        }
        
        if (right_block != NULL) {
            *(void **)(right_block + 2 * ALIGNMENT) = left_block;
        }
    }
    
    if (ptr != mem_head) {
        // Update the head pointer if necessary
        *(void **)(mem_head + 2 * ALIGNMENT) = ptr;
        *(void **)(ptr + ALIGNMENT) = mem_head;
        *(void **)(ptr + 2 * ALIGNMENT) = NULL;
    }
    mem_head = ptr;
    return 0;
}	
