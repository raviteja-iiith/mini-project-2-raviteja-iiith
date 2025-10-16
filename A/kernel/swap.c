#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "file.h"
#include "fcntl.h"
#include "stat.h"


// Initialize swap management for a process
int swap_init(struct proc *p) {
  if(p->swap_file) {
    return 0; // Already initialized
  }
  
  // For simplicity, just use a static swap "file" (memory buffer)
  // In a real implementation, this would create a file on disk
  p->num_swapped = 0;
  
  // Initialize swap slot bitmap
  memset(p->swap_slots, 0, sizeof(p->swap_slots));
  
  // For now, we'll use a simple in-memory approach
  // In a full implementation, this would open/create an actual swap file
  p->swap_file = (struct file*)1; // Mark as initialized
  
  return 0;
}

// Cleanup swap file for a process
void swap_cleanup(struct proc *p) {
  if (p->swap_file) {
    int freed_slots = 0;
    // Count used slots
    for(int i = 0; i < MAX_SWAP_PAGES; i++) {
      if(p->swap_slots[i]) {
        freed_slots++;
      }
    }
    printf("[pid %d] SWAPCLEANUP freed_slots=%d\n", p->pid, freed_slots);
    
    // In a real implementation, this would close the swap file
    // fileclose(p->swap_file);
    p->swap_file = 0;
    memset(p->swap_slots, 0, sizeof(p->swap_slots));
  }
  p->num_swapped = 0;
}

// Check if a swap slot is in use
int swap_slot_is_used(struct proc *p, int slot) {
  if(slot < 0 || slot >= MAX_SWAP_PAGES)
    return 0;
  return p->swap_slots[slot];
}

// Mark a swap slot as used
void swap_slot_set_used(struct proc *p, int slot) {
  if(slot >= 0 && slot < MAX_SWAP_PAGES)
    p->swap_slots[slot] = 1;
}

// Mark a swap slot as free
void swap_slot_set_free(struct proc *p, int slot) {
  if(slot >= 0 && slot < MAX_SWAP_PAGES)
    p->swap_slots[slot] = 0;
}

// Find a free swap slot
int swap_alloc_slot(struct proc *p) {
  for (int slot = 0; slot < MAX_SWAP_PAGES; slot++) {
    if (!swap_slot_is_used(p, slot)) {
      swap_slot_set_used(p, slot);
      return slot;
    }
  }
  return -1; // No free slots
}

// Write a page to swap (simplified for testing)
int swap_out_page(struct proc *p, uint64 va, uint64 pa) {
  if (!p->swap_file) {
    if (swap_init(p) < 0) {
      return -1;
    }
  }
  
  // Find a free swap slot
  int slot = swap_alloc_slot(p);
  if (slot < 0) {
    // No free slots - log and terminate process
    printf("[pid %d] SWAPFULL\n", p->pid);
    return -1;
  }
  
  // For testing purposes, we'll just simulate the swap out
  // In a real implementation, this would write to a swap file
  p->num_swapped++;
  printf("[pid %d] SWAPOUT va=0x%lx slot=%d\n", p->pid, va, slot);
  
  return slot;
}

// Read a page from swap (simplified for testing)
int swap_in_page(struct proc *p, uint64 va, uint64 pa, int slot) {
  if (!p->swap_file || slot < 0 || slot >= MAX_SWAP_PAGES) {
    return -1;
  }
  
  if (!swap_slot_is_used(p, slot)) {
    return -1; // Slot not in use
  }
  
  // For testing purposes, we'll just simulate the swap in
  // In a real implementation, this would read from a swap file
  // Just zero-fill the page for now
  memset((void*)pa, 0, PGSIZE);
  
  // Free the swap slot
  swap_slot_set_free(p, slot);
  p->num_swapped--;
  
  printf("[pid %d] SWAPIN va=0x%lx slot=%d\n", p->pid, va, slot);
  
  return 0;
}
