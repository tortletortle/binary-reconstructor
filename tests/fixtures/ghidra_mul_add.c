#include <stdint.h>

/*
 * This fixture intentionally uses inline assembly to keep the real machine
 * code to two 32-bit arithmetic instructions plus RET. DWARF metadata keeps
 * the function's uint32_t parameter and return ABI visible to Ghidra.
 */
__attribute__((visibility("default"), noinline, used))
uint32_t chrono_mul_add(uint32_t x) {
    uint32_t y;
    __asm__ volatile (
        "imull $5, %%edi, %%eax\n\t"
        "addl $3, %%eax"
        : "=a" (y)
        : "D" (x)
    );
    return y;
}
