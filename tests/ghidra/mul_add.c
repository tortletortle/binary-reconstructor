#include <stdint.h>

#if defined(__GNUC__)
#define CHRONO_EXPORT __attribute__((visibility("default"), noinline))
#else
#define CHRONO_EXPORT
#endif

CHRONO_EXPORT uint32_t mul_add(uint32_t x) {
    return x * 5u + 3u;
}
