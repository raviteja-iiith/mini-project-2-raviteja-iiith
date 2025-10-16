#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"



// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = PTE_R; // Always readable
    if(flags & 0x1)
      perm |= PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

//
// the implementation of the exec() system call
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  // Open the executable file.
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  // Read the ELF header.
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  // Is this really an ELF file?
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // True demand paging - only record segment boundaries, no eager loading
  int num_segments = 0;
  
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
      
    // Store segment info for demand paging (no allocation yet)
    if(num_segments < MAX_SEGMENTS) {
      p->segments[num_segments].va_start = ph.vaddr;
      p->segments[num_segments].va_end = ph.vaddr + ph.memsz;
      p->segments[num_segments].file_offset = ph.off;
      p->segments[num_segments].file_size = ph.filesz;
      p->segments[num_segments].mem_size = ph.memsz;
      p->segments[num_segments].flags = ph.flags;
      num_segments++;
    }
    
    // Update sz to cover all segments, but don't allocate
    if(ph.vaddr + ph.memsz > sz)
      sz = ph.vaddr + ph.memsz;
  }
  
  p->num_segments = num_segments;
  // Initialize demand paging fields
  p = myproc();
  p->num_resident = 0;
  p->next_seq = 0;
  p->num_swapped = 0;
  p->swap_file = 0;
  p->exec_inode = ip; // Keep reference to executable for loading
  idup(ip); // Increment reference count
  p->heap_start = PGROUNDUP(sz);
  
  // Log the truly lazy mapping setup
  uint64 stack_top = TRAPFRAME;
  uint64 text_start = 0, text_end = 0, data_start = 0, data_end = 0;
  for(int i = 0; i < p->num_segments; i++) {
    if(p->segments[i].flags & 0x1) { // Executable
      if(text_start == 0) {
        text_start = p->segments[i].va_start;
        text_end = p->segments[i].va_end;
      } else {
        text_end = p->segments[i].va_end;
      }
    } else { // Data
      if(data_start == 0) {
        data_start = p->segments[i].va_start;
        data_end = p->segments[i].va_end;
      } else {
        data_end = p->segments[i].va_end;
      }
    }
  }
  printf("[pid %d] INIT-LAZYMAP text=[0x%lx,0x%lx) data=[0x%lx,0x%lx) heap_start=0x%lx stack_top=0x%lx\n",
          p->pid, text_start, text_end, data_start, data_end, p->heap_start, stack_top);
  
  // printf("[pid %d] DEBUG: exec setup complete, starting argument copy\n", p->pid);
  
  iunlockput(ip);
  end_op();
  ip = 0;

  uint64 oldsz = p->sz;
  
  // Truly lazy - don't allocate any pages, just set size
  sz = PGROUNDUP(sz);
  uint64 arg_start = sz;
  
  // Minimal pre-allocation for arguments (1 page for basic exec to work)
  uint64 sz1;
  if((sz1 = uvmalloc(pagetable, sz, sz + PGSIZE, PTE_U | PTE_W | PTE_R)) == 0)
    goto bad;
  sz = arg_start + (USERSTACK+1)*PGSIZE; // Full stack size
  
  // Set process size early for demand paging to work during argument copying
  p->sz = sz;
  
  // Set up stack pointers
  sp = sz;
  stackbase = sp - USERSTACK*PGSIZE;

  // Copy argument strings into new stack, remember their
  // addresses in ustack[].
  // printf("[pid %d] DEBUG: starting argv copy, sp=0x%lx, stackbase=0x%lx\n", p->pid, sp, stackbase);
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase)
      goto bad;
    // printf("[pid %d] DEBUG: copying arg %ld to sp=0x%lx\n", p->pid, argc, sp);
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0) {
      // printf("[pid %d] DEBUG: copyout failed for arg %ld\n", p->pid, argc);
      goto bad;
    }
    // printf("[pid %d] DEBUG: arg %ld copied successfully\n", p->pid, argc);
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push a copy of ustack[], the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  // a0 and a1 contain arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->trapframe->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->trapframe->epc = elf.entry;  // initial program counter = main
  p->trapframe->sp = sp; // initial stack pointer
  proc_freepagetable(oldpagetable, oldsz);
  
  // Simple logging for now
  // printf("[pid %d] DEBUG: EXEC completed successfully\n", p->pid);

  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}


