#include "packet_codec.h"

#include <stdio.h>
#include <string.h>

static const char
    *IV_HEX   = "8EA2B7CA516745BF EAfc49904b496089",
    *KEY_HEX  = "279fb74a7572135e 8f9b8ef6d1eee003 69c4e0d86a7b0430 d8cdb78070b4c55a",
    *KEY2_HEX = "0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F",
    *PACKET_HEX = "00000001000000007051434403051b2a8f156efa57a6a19c";

int main(void)
{
    uint8_t iv[16], keypair[64], packet[MCU_PACKET_HEADER_LEN + MCU_XTS_CHUNK_MAX];
    uint8_t plain[MCU_XTS_CHUNK_MAX], packet_out[MCU_PACKET_HEADER_LEN + MCU_XTS_CHUNK_MAX];
    mcu_chunk_meta meta;
    char plain_hex[MCU_XTS_CHUNK_MAX * 2 + 1];
    char packet_hex[sizeof packet * 2 + 1];
    char packet_out_hex[sizeof packet_out * 2 + 1];
    size_t packet_len = 0, plain_len = 0, packet_out_len = 0;

    mcu_hex_to_bytes(IV_HEX, iv);
    mcu_hex_to_bytes(KEY_HEX, keypair);
    mcu_hex_to_bytes(KEY2_HEX, keypair + 32);

    packet_len = mcu_hex_bytes_len(PACKET_HEX);
    mcu_hex_to_bytes(PACKET_HEX, packet);
    if (!mcu_bytes_to_hex(packet, packet_len, packet_hex, sizeof packet_hex))
    {
        puts("packet hex conversion failed");
        return 1;
    }

    if (!mcu_xts_decrypt_packet(keypair, iv, packet, packet_len, plain, sizeof plain, &plain_len)
     || !mcu_bytes_to_hex(plain, plain_len, plain_hex, sizeof plain_hex))
    {
        puts("decrypt failed");
        return 1;
    }

    meta.message_counter = 1U;
    meta.chunk_index = 0;
    meta.flags = 0;
    if (!mcu_xts_encrypt_packet(keypair, iv, &meta, plain, plain_len,
                                packet_out, sizeof packet_out, &packet_out_len)
     || !mcu_bytes_to_hex(packet_out, packet_out_len, packet_out_hex, sizeof packet_out_hex))
    {
        puts("encrypt failed");
        return 1;
    }

    printf("packet in : %s\n", packet_hex);
    printf("plaintext : %s\n", plain_hex);
    printf("packet out: %s\n", packet_out_hex);
    printf("match     : %s\n", packet_len == packet_out_len
                               && memcmp(packet, packet_out, packet_len) == 0 ? "yes" : "no");
    return 0;
}
