#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "memstat.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if(t == SBRK_EAGER || n < 0) {
    if(growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. Pages will be allocated
    // on demand by our page fault handler.
    if(addr + n < addr)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

static int get_page_state(struct proc *p, uint64 va) {
  va = PGROUNDDOWN(va);
  
  // For simplified implementation, check if page is actually mapped
  pte_t *pte = walk(p->pagetable, va, 0);
  if(pte && (*pte & PTE_V)) {
    return RESIDENT;
  }
  
  // Check if page is in valid memory range but not allocated
  if(va >= p->heap_start && va < p->sz) {
    return UNMAPPED;
  }
  
  return UNMAPPED;
}

static int get_page_swap_slot(struct proc *p, uint64 va) {
  return -1; // Simplified implementation
}

static int get_page_seq(struct proc *p, uint64 va) {
  return -1; // Simplified implementation
}

static int get_page_dirty(struct proc *p, uint64 va) {
  return 0; // Simplified implementation
}

uint64
sys_memstat(void)
{
  uint64 info_ptr;
  struct proc *p = myproc();
  
  argaddr(0, &info_ptr);
  
  struct proc_mem_stat stat;
  stat.pid = p->pid;
  stat.num_resident_pages = p->num_resident;
  stat.num_swapped_pages = p->num_swapped;
  stat.next_fifo_seq = p->next_seq;
  
  // Calculate total pages
  uint64 start_addr = 0;
  uint64 end_addr = p->sz;
  
  stat.num_pages_total = (end_addr - start_addr) / PGSIZE;
  if(stat.num_pages_total > MAX_PAGES_INFO) {
    stat.num_pages_total = MAX_PAGES_INFO;
  }
  
  // Fill page information
  int page_count = 0;
  for(uint64 va = start_addr; va < end_addr && page_count < MAX_PAGES_INFO; va += PGSIZE) {
    struct page_stat *ps = &stat.pages[page_count];
    ps->va = va;
    ps->state = get_page_state(p, va);
    ps->is_dirty = get_page_dirty(p, va);
    ps->seq = get_page_seq(p, va);
    ps->swap_slot = get_page_swap_slot(p, va);
    page_count++;
  }
  
  // Copy to user space
  if(copyout(p->pagetable, info_ptr, (char*)&stat, sizeof(stat)) < 0)
    return -1;
    
  return 0;
}
