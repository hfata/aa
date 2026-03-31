#ifndef MCU_PACKET_CODEC_H_
#define MCU_PACKET_CODEC_H_

#include "micro_aes.h"
#include <stddef.h>
#include <stdint.h>

#define MCU_PACKET_HEADER_LEN 8
#define MCU_GCM_CHUNK_MIN 8
#define MCU_GCM_CHUNK_MAX 32
#define MCU_XTS_CHUNK_MIN 16
#define MCU_XTS_CHUNK_MAX 32

typedef struct
{
    unsigned long message_counter;
    unsigned chunk_index;
    uint8_t flags;
} mcu_chunk_meta;

size_t mcu_hex_bytes_len(const char* hex);
void mcu_hex_to_bytes(const char* hex, uint8_t* bytes);
char mcu_bytes_to_hex(const void* data, size_t size, char* hex, size_t hex_cap);

void mcu_build_packet_header(const mcu_chunk_meta* meta, uint8_t header[MCU_PACKET_HEADER_LEN]);
char mcu_parse_packet_header(const uint8_t header[MCU_PACKET_HEADER_LEN], mcu_chunk_meta* meta);

char mcu_pack_chunk(const mcu_chunk_meta* meta,
                    const uint8_t* payload, size_t payload_len,
                    uint8_t* packet, size_t packet_cap, size_t* packet_len);

char mcu_unpack_chunk(const uint8_t* packet, size_t packet_len,
                      mcu_chunk_meta* meta,
                      uint8_t* payload, size_t payload_cap, size_t* payload_len);

#if GCM
char mcu_gcm_encrypt_packet(const uint8_t* key, const uint8_t* iv,
                            const mcu_chunk_meta* meta,
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* packet, size_t packet_cap, size_t* packet_len);

char mcu_gcm_decrypt_packet(const uint8_t* key, const uint8_t* iv,
                            const uint8_t* packet, size_t packet_len,
                            uint8_t* plain, size_t plain_cap, size_t* plain_len);
#endif

#if XTS
char mcu_xts_encrypt_packet(const uint8_t* keys, const uint8_t* iv,
                            const mcu_chunk_meta* meta,
                            const uint8_t* plain, size_t plain_len,
                            uint8_t* packet, size_t packet_cap, size_t* packet_len);

char mcu_xts_decrypt_packet(const uint8_t* keys, const uint8_t* iv,
                            const uint8_t* packet, size_t packet_len,
                            uint8_t* plain, size_t plain_cap, size_t* plain_len);
#endif

#endif
