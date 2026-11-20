#include <stdint.h>
uint32_t transform(uint32_t x){ if(x & 1u) return x*8u+3u; return x ^ 0x55u; }
