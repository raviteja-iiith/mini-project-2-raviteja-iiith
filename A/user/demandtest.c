#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define PAGE_SIZE 4096

int main(int argc, char *argv[])
{
    int safe_mode = 1;       // default
    int swap_test = 0;
    int num_swap_pages = 20; // for swap/FIFO test

    // -----------------------------
    // Parse arguments
    // -----------------------------
    if (argc > 1) {
        if (strcmp(argv[1], "full") == 0) {
            safe_mode = 0;     // triggers invalid access
        } else if (strcmp(argv[1], "swap") == 0) {
            swap_test = 1;     // triggers FIFO swap test
        }
    }

    printf("demandtest: starting test (mode: %s)\n",
           swap_test ? "SWAP/FIFO" : (safe_mode ? "SAFE" : "FULL"));

    int pid = getpid();
    printf("Accessing text/data: PID = %d\n", pid);

    // -----------------------------
    // Heap test
    // -----------------------------
    if (swap_test) {
        // Allocate many pages to trigger swap/FIFO
        char *heap = sbrklazy(num_swap_pages * PAGE_SIZE);
        printf("Reserved %d heap pages at %p\n", num_swap_pages, heap);

        for (int i = 0; i < num_swap_pages; i++) {
            heap[i * PAGE_SIZE] = 'A' + (i % 26);  // triggers ALLOC
            printf("Touched heap page %d\n", i);
        }

        // Re-access first few pages to trigger SWAPIN
        for (int i = 0; i < 5; i++) {
            char c = heap[i * PAGE_SIZE];
            printf("Re-accessed heap page %d, value=%c\n", i, c);
        }
    } else {
        // Small heap test for SAFE/FULL
        int num_pages = 3;
        char *heap = sbrklazy(num_pages * PAGE_SIZE);
        printf("Reserved %d heap pages at %p\n", num_pages, heap);

        for (int i = 0; i < num_pages; i++) {
            heap[i * PAGE_SIZE] = 'A' + i;
            printf("Touched heap page %d\n", i);
        }
    }

    // -----------------------------
    // Stack test
    // -----------------------------
    char stack_buf[PAGE_SIZE];
    stack_buf[0] = 'S';
    stack_buf[PAGE_SIZE - 1] = stack_buf[0];  // marks variable as used
    printf("Stack page touched\n");

    // -----------------------------
    // Invalid memory access (FULL mode only)
    // -----------------------------
    if (!safe_mode && !swap_test) {
        printf("FULL mode: triggering invalid memory access (should kill process)\n");
        char *bad = (char*)0xFFFFFFFFFFFF;
        *bad = 'X';  // terminate process
    } else if (safe_mode) {
        printf("SAFE mode: skipping invalid memory access\n");
    }

    printf("demandtest: finished\n");
    exit(0);
}
