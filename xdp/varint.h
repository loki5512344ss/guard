#ifndef RAMPART_VARINT_H
#define RAMPART_VARINT_H

#include "common.h"

// ── VarInt reader with dual-bounds check ──
// Returns {value, bytes_consumed} on success, goto error on failure
// Fixed: no sign extension UB (shift in u32, cast to s32)
// Fixed: max 5 bytes per Minecraft protocol spec

#define VARINT_BYTE(ptr, pend, dend, max, idx, shift, result)   \
    do {                                                         \
        if ((max) < (idx))                                       \
            goto error;                                          \
        if ((void *)(ptr) + 1 > (void *)(dend))                  \
            goto error;                                          \
        if ((void *)(ptr) + 1 > (void *)(pend))                  \
            goto error;                                          \
        __u8 _b = *(ptr)++;                                      \
        (result) |= ((__u32)(_b & 0x7F) << (shift));             \
        if (!(_b & 0x80))                                        \
            return varint((__s32)(result), (idx));               \
    } while (0)

struct varint_value {
    __s32 value;
    __u8 bytes;
};

static __always_inline struct varint_value varint(__s32 value, __u8 bytes)
{
    struct varint_value v = { .value = value, .bytes = bytes };
    return v;
}

static __always_inline struct varint_value read_varint_sized(
    __u8 *ptr, __u8 *pend, __u8 max, void *dend)
{
    __u32 result = 0;

    VARINT_BYTE(ptr, pend, dend, max, 1, 0,  result);
    VARINT_BYTE(ptr, pend, dend, max, 2, 7,  result);
    VARINT_BYTE(ptr, pend, dend, max, 3, 14, result);
    VARINT_BYTE(ptr, pend, dend, max, 4, 21, result);
    if (max < 5) goto error;
    if ((void *)(ptr) + 1 > (void *)(dend)) goto error;
    if ((void *)(ptr) + 1 > (void *)(pend)) goto error;
    __u8 b5 = *(ptr)++;
    result |= ((__u32)(b5 & 0x7F) << 28);
    result &= 0x7FFFFFFF;
    return varint((__s32)result, 5);

error:
    return varint(0, 0);
}

// Convenience: read varint with max=5 (full Minecraft varint)
static __always_inline struct varint_value read_varint(__u8 *ptr, __u8 *pend, void *dend)
{
    return read_varint_sized(ptr, pend, 5, dend);
}

#endif /* RAMPART_VARINT_H */
