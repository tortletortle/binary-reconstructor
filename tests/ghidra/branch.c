#include <stdint.h>

#if defined(__GNUC__)
#define CHRONO_EXPORT __attribute__((visibility("default"), noinline))
#else
#define CHRONO_EXPORT
#endif

CHRONO_EXPORT uint32_t branch_transform(uint32_t x) {
    if (x < 10u) {
        return x + 1u;
    }
    return x * 2u + 3u;
}

CHRONO_EXPORT uint32_t branch_join(uint32_t x) {
    uint32_t value;
    if ((x & 1u) == 0u) {
        value = x + 7u;
    } else {
        value = x * 3u;
    }
    return value ^ 0x55u;
}

CHRONO_EXPORT uint32_t nested_branch(uint32_t x) {
    if (x < 10u) {
        return x + 1u;
    }
    if (x < 100u) {
        return x * 2u + 3u;
    }
    return x ^ 0x55u;
}

CHRONO_EXPORT uint32_t branch_three_way(uint32_t x) {
    uint32_t value;
    if (x < 10u) {
        value = x + 1u;
    } else if (x < 100u) {
        value = x * 2u + 3u;
    } else {
        value = x ^ 0x55u;
    }
    return value + 7u;
}
