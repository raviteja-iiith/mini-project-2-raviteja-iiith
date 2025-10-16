#include "kernel/types.h"
#include "kernel/memstat.h"
#include "user/user.h"

int main() {
  printf("Demand Paging Test\n");
  
  // Test lazy sbrk allocation
  char *p = sbrklazy(4096 * 2);
  if(p == (char*)-1) {
    printf("sbrk failed\n");
    exit(1);
  }
  printf("Allocated 2 pages at %p\n", p);
  
  // Access the first page (should trigger page fault)
  printf("Writing to first page...\n");
  p[0] = 'A';
  p[100] = 'B';
  printf("First page written\n");
  
  // Access the second page (should trigger another page fault)  
  printf("Writing to second page...\n");
  p[4096] = 'C';
  p[4096 + 100] = 'D';
  printf("Second page written\n");
  
  // Test memstat system call
  struct proc_mem_stat stat;
  if(memstat(&stat) == 0) {
    printf("memstat: PID=%d resident=%d swapped=%d total=%d next_seq=%d\n", 
           stat.pid, stat.num_resident_pages, stat.num_swapped_pages,
           stat.num_pages_total, stat.next_fifo_seq);
  } else {
    printf("memstat failed\n");
  }
  
  printf("Test completed\n");
  exit(0);
}