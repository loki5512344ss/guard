#ifndef RAMPART_PROTOCOL_H
#define RAMPART_PROTOCOL_H

#include "common.h"
#include "varint.h"

// ── Handshake inspector ──
// Returns: pseudo-state for next action, or 0 on failure
//   DIRECT_READ_LOGIN  — handshake + login in same segment
//   DIRECT_READ_STATUS — handshake + status in same segment
//   AWAIT_LOGIN        — handshake only, wait for login
//   AWAIT_STATUS       — handshake only, wait for status req
//   RECEIVED_LEGACY_PING — 0xFE legacy ping
//   0                  — parse error

#define DIRECT_READ_LOGIN        100
#define DIRECT_READ_STATUS      101
#define RECEIVED_LEGACY_PING    102

static __always_inline __s32 inspect_handshake(
    __u8 **cursor, __u8 *payload_end, __s32 *protocol, void *data_end)
{
    __u8 *ptr = *cursor;

    // Legacy ping check (0xFE)
    CHECK_BOUNDS_OR_RETURN(ptr, 1, payload_end, data_end);
    if (ptr[0] == (__u8)0xFE) {
        return RECEIVED_LEGACY_PING;
    }

    // Read total packet length
    struct varint_value pkt_len = read_varint(ptr, payload_end, data_end);
    if (pkt_len.bytes == 0) goto error;
    ptr += pkt_len.bytes;

    // Packet ID must be 0 (Handshake)
    CHECK_BOUNDS_OR_RETURN(ptr, 1, payload_end, data_end);
    struct varint_value pkid = read_varint(ptr, payload_end, data_end);
    if (pkid.bytes == 0 || pkid.value != 0) goto error;
    ptr += pkid.bytes;

    // Protocol version
    struct varint_value pv = read_varint(ptr, payload_end, data_end);
    if (pv.bytes == 0 || pv.value < 0) goto error;
    *protocol = pv.value;
    ptr += pv.bytes;

    // Server address (varint-length-prefixed string, max 765 bytes)
    struct varint_value addr_len = read_varint(ptr, payload_end, data_end);
    if (addr_len.bytes == 0 || addr_len.value < 0 || addr_len.value > 765)
        goto error;
    ptr += addr_len.bytes;

    CHECK_BOUNDS_OR_RETURN(ptr, addr_len.value, payload_end, data_end);
    ptr += addr_len.value;

    // Server port (u16)
    CHECK_BOUNDS_OR_RETURN(ptr, 2, payload_end, data_end);
    // __u16 port = (ptr[0] << 8) | ptr[1]; — skip, not used
    ptr += 2;

    // Next state (1=status, 2=login, 3=transfer since 1.20.5)
    struct varint_value ns = read_varint(ptr, payload_end, data_end);
    if (ns.bytes == 0) goto error;
    if (ns.value != 1 && ns.value != 2 && ns.value != 3) goto error;
    ptr += ns.bytes;

    // Verify declared length matches consumed
    __u32 consumed = (__u32)(ptr - *cursor);
    __u32 declared_len = (__u32)(pkt_len.value + pkt_len.bytes);
    if (consumed > declared_len) goto error;

    *cursor = ptr;

    // Check if more data follows in same segment
    if (consumed < declared_len + 2) {
        // Handshake only — return expected next state
        return (ns.value == 1) ? 103 /* AWAIT_STATUS */ : 104 /* AWAIT_LOGIN */;
    }

    // More data present — return direct-read state
    return (ns.value == 1) ? DIRECT_READ_STATUS : DIRECT_READ_LOGIN;

error:
    return 0;
}

// ── LoginStart inspector ──
static __always_inline __u8 inspect_login_packet(
    __u8 *ptr, __u8 *payload_end, __s32 protocol, void *data_end)
{
    // Packet length
    struct varint_value pkt_len = read_varint(ptr, payload_end, data_end);
    if (pkt_len.bytes == 0) goto error;
    ptr += pkt_len.bytes;

    // Packet ID must be 0 (LoginStart)
    struct varint_value pkid = read_varint(ptr, payload_end, data_end);
    if (pkid.bytes == 0 || pkid.value != 0) goto error;
    ptr += pkid.bytes;

    // Username (varint-length-prefixed string)
    struct varint_value name_len = read_varint(ptr, payload_end, data_end);
    if (name_len.bytes == 0 || name_len.value <= 0) goto error;
    ptr += name_len.bytes;

    __s32 max_name = (protocol >= 764) ? 16 : 48; // 1.20.2+ uses 16
    if (name_len.value > max_name || name_len.value > 48) goto error;

    CHECK_BOUNDS_OR_RETURN(ptr, name_len.value, payload_end, data_end);
    // Skip username bytes
    ptr += name_len.value;

    // For 1.19.1+ (protocol >= 760): optional UUID
    if (protocol >= 760) {
        CHECK_BOUNDS_OR_RETURN(ptr, 1, payload_end, data_end);
        __u8 has_uuid = ptr[0];
        ptr += 1;
        if (has_uuid) {
            CHECK_BOUNDS_OR_RETURN(ptr, 16, payload_end, data_end);
            ptr += 16; // skip UUID
        }
    }

    // For 1.19-1.19.2 (759-760): optional public key
    if (protocol >= 759 && protocol < 761) {
        CHECK_BOUNDS_OR_RETURN(ptr, 1, payload_end, data_end);
        __u8 has_key = ptr[0];
        ptr += 1;
        if (has_key) {
            // Expiry (long)
            CHECK_BOUNDS_OR_RETURN(ptr, 8, payload_end, data_end);
            ptr += 8;
            // Key length (varint)
            struct varint_value key_len = read_varint(ptr, payload_end, data_end);
            if (key_len.bytes == 0) goto error;
            ptr += key_len.bytes;
            CHECK_BOUNDS_OR_RETURN(ptr, key_len.value, payload_end, data_end);
            ptr += key_len.value;
            // Signature length (varint)
            struct varint_value sig_len = read_varint(ptr, payload_end, data_end);
            if (sig_len.bytes == 0) goto error;
            ptr += sig_len.bytes;
            CHECK_BOUNDS_OR_RETURN(ptr, sig_len.value, payload_end, data_end);
            ptr += sig_len.value;
        }
    }

    return 1; // success

error:
    return 0;
}

// ── Status request inspector ──
// Must be: [len=0x01][id=0x00]
static __always_inline __u8 inspect_status_request(
    __u8 *ptr, __u8 *payload_end, void *data_end)
{
    CHECK_BOUNDS_OR_RETURN(ptr, 2, payload_end, data_end);
    if (ptr[0] != 0x01 || ptr[1] != 0x00)
        goto error;
    return 1;

error:
    return 0;
}

// ── Ping request inspector ──
// Must be: [len=0x09][id=0x01][8 byte timestamp/long]
static __always_inline __u8 inspect_ping_request(
    __u8 *ptr, __u8 *payload_end, void *data_end)
{
    CHECK_BOUNDS_OR_RETURN(ptr, 10, payload_end, data_end);
    if (ptr[0] != 0x09 || ptr[1] != 0x01)
        goto error;
    return 1;

error:
    return 0;
}

#endif /* RAMPART_PROTOCOL_H */
