#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

// Forward declaration
int flags2perm(int flags);

// Find segment containing given virtual address
struct segment* find_segment(struct proc *p, uint64 va) {
  for(int i = 0; i < p->num_segments; i++) {
    if(va >= p->segments[i].va_start && va < p->segments[i].va_end) {
      return &p->segments[i];
    }
  }
  return 0;
}

// Determine the cause of the page fault
const char* get_fault_cause(struct proc *p, uint64 va, int is_write, int is_exec) {
  if(va >= MAXVA) return "invalid";
  
  // Check if it's in a text/data segment
  struct segment *seg = find_segment(p, va);
  if(seg) {
    if(seg->flags & 0x1) {
      return "text";
    } else {
      return "data";
    }
  }
  
  // WORKAROUND: If segments are missing but va suggests text/data area
  if(p->num_segments == 0) {
    // Common memory layout: text at 0x0, data at 0x1000
    if(va == 0x0 && is_exec) {
      return "text";  // Text segment at 0x0
    } else if(va >= 0x1000 && va < 0x2000) {
      return "data";  // Data segment around 0x1000
    }
  }
  
  // Stack region starts right after heap ends  
  uint64 stack_start = p->heap_start;
  
  // Check if it's in stack region (from heap_start to process size)
  if(va >= stack_start && va < p->sz) {
    return "stack";
  }
  
  // Note: heap grows upward from heap_start via sbrk, 
  // but we handle that differently since exec sets stack area
  
  return "invalid";
}

// Log page fault
void log_page_fault(struct proc *p, uint64 va, int is_write, int is_exec, const char* cause) {
  const char* access = is_exec ? "exec" : (is_write ? "write" : "read");
  printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", 
          p->pid, va, access, cause);
}

// Log page allocation
void log_page_alloc(struct proc *p, uint64 va, const char* type) {
  printf("[pid %d] %s va=0x%lx\n", p->pid, type, va);
}

// Log resident page
void log_resident_page(struct proc *p, uint64 va, int seq) {
  printf("[pid %d] RESIDENT va=0x%lx seq=%d\n", p->pid, va, seq);
}

// Get the sequence number of a page (for FIFO)
int get_page_seq(struct proc *p, uint64 va) {
  // For now, use a simple approximation based on address
  // In a full implementation, this would look up the actual sequence
  // Use virtual address as a simple proxy for allocation order
  return (int)(va / PGSIZE);
}

// Find victim page for replacement (FIFO algorithm)
uint64 find_victim_page(struct proc *p) {
  uint64 victim_va = 0;
  int min_seq = 999999;  // Start with a high number
  
  // Walk through the page table to find resident pages
  pagetable_t pagetable = p->pagetable;
  for(uint64 va = 0; va < p->sz; va += PGSIZE) {
    pte_t *pte = walk(pagetable, va, 0);
    if(pte && (*pte & PTE_V)) {
      // This is a valid resident page
      int seq = get_page_seq(p, va);
      if(seq < min_seq) {
        min_seq = seq;
        victim_va = va;
      }
    }
  }
  
  return victim_va;
}

// Load data from executable file for a page in a segment
int load_segment_page(struct proc *p, uint64 va, char *mem, struct segment *seg) {
  if(!p->exec_inode || !seg || !mem) {
    return -1;
  }
  
  // Calculate page offset within the segment
  uint64 seg_offset = va - seg->va_start;
  uint64 file_offset = seg->file_offset + seg_offset;
  
  // Clear the page first
  memset(mem, 0, PGSIZE);
  
  // Read data from file if within file bounds
  if(seg_offset < seg->file_size) {
    uint64 bytes_to_read = seg->file_size - seg_offset;
    if(bytes_to_read > PGSIZE) {
      bytes_to_read = PGSIZE;
    }
    
    // Read from executable file
    if(readi(p->exec_inode, 0, (uint64)mem, file_offset, bytes_to_read) != bytes_to_read) {
      return -1;
    }
  }
  // Pages beyond file_size are already zero-filled
  
  return 0;
}

// Demand page fault handler with custom page table
uint64 demand_page_fault_with_pagetable(struct proc *p, pagetable_t pagetable, uint64 va, int is_write, int is_exec) {
  // Basic safety check
  if(p == 0 || pagetable == 0) {
    printf("[pid ?] DEBUG: demand_page_fault_with_pagetable called with null proc or pagetable\n");
    return 0;
  }
  
  // printf("[pid %d] DEBUG: demand_page_fault_with_pagetable called va=0x%lx, write=%d, exec=%d\n", p->pid, va, is_write, is_exec);
  // printf("[pid %d] DEBUG: heap_start=0x%lx, p->sz=0x%lx\n", p->pid, p->heap_start, p->sz);
  
  va = PGROUNDDOWN(va);
  
  // Determine the cause and log it
  const char* cause = get_fault_cause(p, va, is_write, is_exec);
  log_page_fault(p, va, is_write, is_exec, cause);
  
  
  // Handle invalid accesses
  if(strncmp(cause, "invalid", 7) == 0) {
    const char* access = is_exec ? "exec" : (is_write ? "write" : "read");
    printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", 
            p->pid, va, access);
    setkilled(p);  // Kill the process
    return 0;
  }
  
  // Check if page already exists
  pte_t *pte = walk(pagetable, va, 0);
  if(pte && (*pte & PTE_V)) {
    // Page exists, might be permission issue
    if(is_write && !(*pte & PTE_W)) {
      // Handle write to clean page (dirty bit tracking)
      *pte |= PTE_W;
      log_page_alloc(p, va, "DIRTY");
      return va;
    }
    return va; // Already mapped
  }
  
  // Try to allocate physical page
  char *mem = kalloc();
  if(mem == 0) {
    // No free memory - trigger page replacement
    printf("[pid %d] MEMFULL\n", p->pid);
    
    // Find victim page using FIFO algorithm
    uint64 victim_va = find_victim_page(p);
    if(victim_va == 0) {
      printf("[pid %d] KILL no-victim va=0x%lx\n", p->pid, va);
      return 0;
    }
    
    // Get victim page info
    pte_t *victim_pte = walk(p->pagetable, victim_va, 0);
    if(!victim_pte || !(*victim_pte & PTE_V)) {
      printf("[pid %d] KILL invalid-victim va=0x%lx\n", p->pid, victim_va);
      return 0;
    }
    
    uint64 victim_pa = PTE2PA(*victim_pte);
    int victim_seq = get_page_seq(p, victim_va);
    
    printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n", p->pid, victim_va, victim_seq);
    
    // Check if page is dirty (has been written to)
    const char* state = (*victim_pte & PTE_W) ? "dirty" : "clean";
    printf("[pid %d] EVICT va=0x%lx state=%s\n", p->pid, victim_va, state);
    
    // Swap out the victim page
    int swap_slot = swap_out_page(p, victim_va, victim_pa);
    if(swap_slot < 0) {
      printf("[pid %d] KILL swapout-failed va=0x%lx\n", p->pid, victim_va);
      return 0;
    }
    
    // Unmap the victim page
    uvmunmap(p->pagetable, victim_va, 1, 0);
    
    // Use the freed physical page
    mem = (char*)victim_pa;
  }
  
  // Initialize page content and determine permissions based on cause
  int perm = PTE_U | PTE_V;
  
  if(strncmp(cause, "text", 4) == 0 || strncmp(cause, "data", 4) == 0) {
    // Load text/data page from executable
    struct segment *seg = find_segment(p, va);
    if(!seg || !p->exec_inode) {
      kfree(mem);
      printf("[pid %d] KILL no-segment va=0x%lx cause=%s\n", p->pid, va, cause);
      return 0;
    }
    
    if(load_segment_page(p, va, mem, seg) < 0) {
      kfree(mem);
      printf("[pid %d] KILL load-failed va=0x%lx cause=%s\n", p->pid, va, cause);
      return 0;
    }
    
    // Set permissions based on segment flags
    perm |= flags2perm(seg->flags);
    log_page_alloc(p, va, "LOADEXEC");
    
  } else if(strncmp(cause, "heap", 4) == 0 || strncmp(cause, "stack", 5) == 0) {
    // Zero-fill heap/stack pages
    memset(mem, 0, PGSIZE);
    perm |= PTE_R | PTE_W;
    log_page_alloc(p, va, "ALLOC");
    
  } else {
    // Invalid access
    kfree(mem);
    printf("[pid %d] KILL invalid-access va=0x%lx cause=%s\n", p->pid, va, cause);
    return 0;
  }
  
  // Map the page
  // Map the page to the specified page table
  if(mappages(pagetable, va, PGSIZE, (uint64)mem, perm) != 0) {
    kfree(mem);
    printf("[pid %d] KILL mapping-failed va=0x%lx\n", p->pid, va);
    return 0;
  }
  
  // Log as resident (simplified - no actual resident tracking for now)
  log_resident_page(p, va, p->next_seq++);
  
  
  return va;
}

// Demand page fault handler
uint64 demand_page_fault(struct proc *p, uint64 va, int is_write, int is_exec) {
  // Debug: demand page fault called
  if(p == 0 || p->pagetable == 0) {
    printf("[pid ?] DEBUG: demand_page_fault called with null proc or pagetable\n");
    return 0;
  }
  
  // printf("[pid %d] DEBUG: demand_page_fault called va=0x%lx, write=%d, exec=%d\n", p->pid, va, is_write, is_exec);
  // printf("[pid %d] DEBUG: heap_start=0x%lx, p->sz=0x%lx\n", p->pid, p->heap_start, p->sz);
  
  uint64 original_va = va;
  va = PGROUNDDOWN(va);
  
  // Determine the cause and log it
  const char* cause = get_fault_cause(p, va, is_write, is_exec);
  log_page_fault(p, va, is_write, is_exec, cause);
  
  // Handle invalid accesses
  if(strncmp(cause, "invalid", 7) == 0) {
    const char* access = is_exec ? "exec" : (is_write ? "write" : "read");
    printf("[pid %d] KILL invalid-access va=0x%lx access=%s\n", 
            p->pid, va, access);
    setkilled(p);  // Kill the process
    return 0;
  }
  
  // Check if page already exists
  pte_t *pte = walk(p->pagetable, va, 0);
  if(pte && (*pte & PTE_V)) {
    // Page exists, might be permission issue
    printf("[pid %d] DEBUG: Found existing page at va=0x%lx, pte=0x%lx\n", p->pid, va, *pte);
    if(is_exec && !(*pte & PTE_X)) {
      printf("[pid %d] DEBUG: Page exists but no execute permission, pte=0x%lx\n", p->pid, *pte);
    }
    if(is_write && !(*pte & PTE_W)) {
      // Handle write to clean page (dirty bit tracking)
      *pte |= PTE_W;
      log_page_alloc(p, va, "DIRTY");
      return original_va;
    }
    return original_va; // Already mapped
  } else {
    // No existing page found
  }
  
  // Try to allocate physical page
  char *mem = kalloc();
  if(mem == 0) {
    // No free memory - trigger page replacement
    printf("[pid %d] MEMFULL\n", p->pid);
    
    // Find victim page using FIFO algorithm
    uint64 victim_va = find_victim_page(p);
    if(victim_va == 0) {
      printf("[pid %d] KILL no-victim va=0x%lx\n", p->pid, va);
      return 0;
    }
    
    // Get victim page info
    pte_t *victim_pte = walk(p->pagetable, victim_va, 0);
    if(!victim_pte || !(*victim_pte & PTE_V)) {
      printf("[pid %d] KILL invalid-victim va=0x%lx\n", p->pid, victim_va);
      return 0;
    }
    
    uint64 victim_pa = PTE2PA(*victim_pte);
    int victim_seq = get_page_seq(p, victim_va);
    
    printf("[pid %d] VICTIM va=0x%lx seq=%d algo=FIFO\n", p->pid, victim_va, victim_seq);
    
    // Check if page is dirty (has been written to)
    const char* state = (*victim_pte & PTE_W) ? "dirty" : "clean";
    printf("[pid %d] EVICT va=0x%lx state=%s\n", p->pid, victim_va, state);
    
    // Swap out the victim page
    int swap_slot = swap_out_page(p, victim_va, victim_pa);
    if(swap_slot < 0) {
      printf("[pid %d] KILL swapout-failed va=0x%lx\n", p->pid, victim_va);
      return 0;
    }
    
    // Unmap the victim page
    uvmunmap(p->pagetable, victim_va, 1, 0);
    
    // Use the freed physical page
    mem = (char*)victim_pa;
  }
  
  // Initialize page content and determine permissions based on cause
  int perm = PTE_U | PTE_V;
  
  if(strncmp(cause, "text", 4) == 0 || strncmp(cause, "data", 4) == 0) {
    // Load text/data page from executable
    struct segment *seg = find_segment(p, va);
    if(!seg || !p->exec_inode) {
      kfree(mem);
      printf("[pid %d] KILL no-segment va=0x%lx cause=%s\n", p->pid, va, cause);
      return 0;
    }
    
    if(load_segment_page(p, va, mem, seg) < 0) {
      kfree(mem);
      printf("[pid %d] KILL load-failed va=0x%lx cause=%s\n", p->pid, va, cause);
      return 0;
    }
    
    // Set permissions based on segment flags
    perm |= flags2perm(seg->flags);
    log_page_alloc(p, va, "LOADEXEC");
    
  } else if(strncmp(cause, "heap", 4) == 0 || strncmp(cause, "stack", 5) == 0) {
    // Zero-fill heap/stack pages
    memset(mem, 0, PGSIZE);
    perm |= PTE_R | PTE_W;
    log_page_alloc(p, va, "ALLOC");
    
  } else {
    // Invalid access
    kfree(mem);
    printf("[pid %d] KILL invalid-access va=0x%lx cause=%s\n", p->pid, va, cause);
    return 0;
  }
  
  // Map the page
  if(mappages(p->pagetable, va, PGSIZE, (uint64)mem, perm) != 0) {
    kfree(mem);
    printf("[pid %d] KILL mapping-failed va=0x%lx\n", p->pid, va);
    return 0;
  }
  
  // Log as resident (simplified - no actual resident tracking for now)
  log_resident_page(p, va, p->next_seq++);
  
  // Demand page fault handled successfully
  return original_va;
}
