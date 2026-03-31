#include "packet_codec.h"

#include <stdio.h>
#include <string.h>

#define MCU_GCM_AAD_LEN 8
#if GCM
#define MCU_MAX_RECORD_PAYLOAD (MCU_GCM_CHUNK_MAX + GCM_TAG_LEN)
#else
#define MCU_MAX_RECORD_PAYLOAD MCU_XTS_CHUNK_MAX
#endif

static void store_be16(uint8_t* out, unsigned value)
{
    out[0] = (uint8_t) (value >> 8);
    out[1] = (uint8_t) value;
}

static void store_be32(uint8_t* out, unsigned long value)
{
    out[0] = (uint8_t) (value >> 24);
    out[1] = (uint8_t) (value >> 16);
    out[2] = (uint8_t) (value >> 8);
    out[3] = (uint8_t) value;
}

static unsigned load_be16(const uint8_t* in)
{
    return ((unsigned) in[0] << 8) | in[1];
}

static unsigned long load_be32(const uint8_t* in)
{
    return ((unsigned long) in[0] << 24) | ((unsigned long) in[1] << 16)
         | ((unsigned long) in[2] << 8) | in[3];
}

static void store_le32(uint8_t* out, unsigned long value)
{
    out[0] = (uint8_t) value;
    out[1] = (uint8_t) (value >> 8);
    out[2] = (uint8_t) (value >> 16);
    out[3] = (uint8_t) (value >> 24);
}

size_t mcu_hex_bytes_len(const char* hex)
{
    size_t digits = 0;

    for (; *hex; ++hex)
        if (('0' <= *hex && *hex <= '9') || ('A' <= *hex && *hex <= 'F')
         || ('a' <= *hex && *hex <= 'f')) ++digits;
    return digits / 2;
}

void mcu_hex_to_bytes(const char* hex, uint8_t* bytes)
{
    unsigned shl = 0;

    for (--bytes; *hex; ++hex)
    {
        if ((*hex < '0' || '9' < *hex) && (*hex < 'A' || 'F' < *hex)
         && (*hex < 'a' || 'f' < *hex)) continue;
        if ((shl ^= 4) != 0) *++bytes = 0;
        *bytes |= (*hex % 16 + (*hex > '9') * 9) << shl;
    }
}

char mcu_bytes_to_hex(const void* data, size_t size, char* hex, size_t hex_cap)
{
    const uint8_t* bytes = (const uint8_t*) data;
    size_t i;

    if (hex_cap < size * 2 + 1) return 0;
    for (i = 0; i != size; ++i)
        sprintf(hex + i * 2, "%02x", bytes[i]);
    hex[size * 2] = '\0';
    return 1;
}

void mcu_build_packet_header(const mcu_chunk_meta* meta, uint8_t header[MCU_PACKET_HEADER_LEN])
{
    store_be32(header, meta->message_counter);
    store_be16(header + 4, meta->chunk_index);
    header[6] = meta->flags;
    header[7] = 0;
}

char mcu_parse_packet_header(const uint8_t header[MCU_PACKET_HEADER_LEN], mcu_chunk_meta* meta)
{
    if (!header || !meta) return 0;

    meta->message_counter = load_be32(header);
    meta->chunk_index = load_be16(header + 4);
    meta->flags = header[6];
    return 1;
}

char mcu_pack_chunk(const mcu_chunk_meta* meta,
                    const uint8_t* payload, size_t payload_len,
                    uint8_t* packet, size_t packet_cap, size_t* packet_len)
{
    if (!meta || !payload || !packet || !packet_len) return 0;
    if (packet_cap < MCU_PACKET_HEADER_LEN + payload_len) return 0;

    mcu_build_packet_header(meta, packet);
    memcpy(packet + MCU_PACKET_HEADER_LEN, payload, payload_len);
    *packet_len = MCU_PACKET_HEADER_LEN + payload_len;
    return 1;
}

char mcu_unpack_chunk(const uint8_t* packet, size_t packet_len,
                      mcu_chunk_meta* meta,
                      uint8_t* payload, size_t payload_cap, size_t* payload_len)
{
    if (!packet || !meta || !payload || !payload_len) return 0;
    if (packet_len < MCU_PACKET_HEADER_LEN) return 0;

    *payload_len = packet_len - MCU_PACKET_HEADER_LEN;
    if (*payload_len > payload_cap) return 0;

    if (!mcu_parse_packet_header(packet, meta)) return 0;
    memcpy(payload, packet + MCU_PACKET_HEADER_LEN, *payload_len);
    return 1;
}

#if GCM
static char valid_gcm_chunk_len(size_t plain_len)
{
    return plain_len == 8 || plain_len == 16 || plain_len == 32;
}

static void make_gcm_aad(const mcu_chunk_meta* meta, uint8_t aad[MCU_GCM_AAD_LEN])
{
    mcu_build_packet_header(meta, aad);
}

static void make_gcm_nonce(const uint8_t* iv, const mcu_chunk_meta* meta,
                           uint8_t nonce[GCM_NONCE_LEN])
{
    memcpy(nonce, iv, 4);
    store_be32(nonce + 4, meta->message_counter);
    store_be32(nonce + 8, meta->chunk_index);
}

char mcu_gcm_encrypt_packet(const uint8_t* key, const uint8_t* iv,
                            const mcu_chunk_meta* meta,
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* packet, size_t packet_cap, size_t* packet_len)
{
    uint8_t aad[MCU_GCM_AAD_LEN], nonce[GCM_NONCE_LEN];
    uint8_t payload[MCU_MAX_RECORD_PAYLOAD];

    if (!key || !iv || !meta || !plain || !packet || !packet_len) return 0;
    if (!valid_gcm_chunk_len(plain_len)) return 0;

    make_gcm_aad(meta, aad);
    make_gcm_nonce(iv, meta, nonce);
    AES_GCM_encrypt(key, nonce, aad, sizeof aad, plain, plain_len, payload);
    return mcu_pack_chunk(meta, payload, plain_len + GCM_TAG_LEN, packet, packet_cap, packet_len);
}

char mcu_gcm_decrypt_packet(const uint8_t* key, const uint8_t* iv,
                            const uint8_t* packet, size_t packet_len,
                            uint8_t* plain, size_t plain_cap, size_t* plain_len)
{
    mcu_chunk_meta meta;
    uint8_t aad[MCU_GCM_AAD_LEN], nonce[GCM_NONCE_LEN];
    uint8_t payload[MCU_MAX_RECORD_PAYLOAD];
    size_t payload_len = 0;

    if (!key || !iv || !packet || !plain || !plain_len) return 0;
    if (!mcu_unpack_chunk(packet, packet_len, &meta, payload, sizeof payload, &payload_len)) return 0;
    if (payload_len < GCM_TAG_LEN) return 0;

    *plain_len = payload_len - GCM_TAG_LEN;
    if (!valid_gcm_chunk_len(*plain_len) || *plain_len > plain_cap) return 0;

    make_gcm_aad(&meta, aad);
    make_gcm_nonce(iv, &meta, nonce);
    return AES_GCM_decrypt(key, nonce, aad, sizeof aad, payload, *plain_len, plain) == 0;
}
#endif

#if XTS
static char valid_xts_chunk_len(size_t plain_len)
{
    return plain_len == 16 || plain_len == 32;
}

static void make_xts_tweak(const uint8_t* iv, const mcu_chunk_meta* meta, uint8_t tweak[16])
{
    memcpy(tweak, iv, 8);
    store_le32(tweak + 8, meta->message_counter);
    store_le32(tweak + 12, meta->chunk_index);
}

char mcu_xts_encrypt_packet(const uint8_t* keys, const uint8_t* iv,
                            const mcu_chunk_meta* meta,
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* packet, size_t packet_cap, size_t* packet_len)
{
    uint8_t payload[MCU_XTS_CHUNK_MAX];
    uint8_t tweak[16];

    if (!keys || !iv || !meta || !plain || !packet || !packet_len) return 0;
    if (!valid_xts_chunk_len(plain_len)) return 0;

    make_xts_tweak(iv, meta, tweak);
    if (AES_XTS_encrypt(keys, tweak, plain, plain_len, payload)) return 0;
    return mcu_pack_chunk(meta, payload, plain_len, packet, packet_cap, packet_len);
}

char mcu_xts_decrypt_packet(const uint8_t* keys, const uint8_t* iv,
                            const uint8_t* packet, size_t packet_len,
                            uint8_t* plain, size_t plain_cap, size_t* plain_len)
{
    mcu_chunk_meta meta;
    uint8_t payload[MCU_XTS_CHUNK_MAX];
    uint8_t tweak[16];
    size_t payload_len = 0;

    if (!keys || !iv || !packet || !plain || !plain_len) return 0;
    if (!mcu_unpack_chunk(packet, packet_len, &meta, payload, sizeof payload, &payload_len)) return 0;
    if (!valid_xts_chunk_len(payload_len) || payload_len > plain_cap) return 0;

    make_xts_tweak(iv, &meta, tweak);
    if (AES_XTS_decrypt(keys, tweak, payload, payload_len, plain)) return 0;
    *plain_len = payload_len;
    return 1;
}
#endif
