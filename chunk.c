#include "chunk.h"

#if CHUNK_GCM_DEMO || CHUNK_XTS_DEMO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_CAP 128

static void hex2bytes(const char* hex, uint8_t* bytes)
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

static size_t hexbytes_len(const char* hex)
{
    size_t digits = 0;

    for (; *hex; ++hex)
        if (('0' <= *hex && *hex <= '9') || ('A' <= *hex && *hex <= 'F')
         || ('a' <= *hex && *hex <= 'f')) ++digits;
    return digits / 2;
}

static void* alloc_bytes(size_t size)
{
    return malloc(size ? size : 1);
}

static char append_hex_line(FILE* file, const void* data, size_t size)
{
    const uint8_t* bytes = (const uint8_t*) data;

    while (size--)
        if (fprintf(file, "%02x", *bytes++) < 0) return 0;
    return fputc('\n', file) != EOF;
}

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

static void store_le32(uint8_t* out, unsigned long value)
{
    out[0] = (uint8_t) value;
    out[1] = (uint8_t) (value >> 8);
    out[2] = (uint8_t) (value >> 16);
    out[3] = (uint8_t) (value >> 24);
}

static char write_chunk_record(FILE* file, unsigned long msg_counter, unsigned chunk_index,
                               uint8_t flags, const void* cipher, size_t cipher_len)
{
    const uint8_t* bytes = (const uint8_t*) cipher;

    if (fprintf(file, "%lu|%u|%u|", msg_counter, chunk_index, flags) < 0)
        return 0;
    while (cipher_len--)
        if (fprintf(file, "%02x", *bytes++) < 0) return 0;
    return fputc('\n', file) != EOF;
}

static char parse_chunk_record(char* line, unsigned long* msg_counter, unsigned* chunk_index,
                               uint8_t* flags, uint8_t** cipher, size_t* cipher_len)
{
    char *field[4], *next = line, *endptr = NULL;
    unsigned long value;
    size_t i;

    for (i = 0; i != 4; ++i)
    {
        field[i] = next;
        next = i == 3 ? NULL : strchr(field[i], '|');
        if (i != 3)
        {
            if (!next) return 0;
            *next++ = '\0';
        }
    }

    value = strtoul(field[0], &endptr, 10);
    if (*endptr) return 0;
    *msg_counter = value;

    value = strtoul(field[1], &endptr, 10);
    if (*endptr) return 0;
    *chunk_index = (unsigned) value;

    value = strtoul(field[2], &endptr, 10);
    if (*endptr || value > 0xFFU) return 0;
    *flags = (uint8_t) value;

    for (next = field[3]; *next == ' ' || *next == '\t'; ++next) { }
    for (endptr = next + strlen(next); endptr != next; )
        if (*--endptr == '\r' || *endptr == '\n') *endptr = '\0';
        else break;

    *cipher_len = hexbytes_len(next);
    *cipher = alloc_bytes(*cipher_len);
    if (!*cipher) return 0;
    hex2bytes(next, *cipher);
    return 1;
}

static void make_gcm_nonce(const uint8_t* iv, unsigned long msg_counter,
                           unsigned chunk_index, uint8_t nonce[GCM_NONCE_LEN])
{
    memcpy(nonce, iv, 4);
    store_be32(nonce + 4, msg_counter);
    store_be32(nonce + 8, chunk_index);
}

static void make_xts_tweak(const uint8_t* iv, unsigned long msg_counter,
                           unsigned chunk_index, uint8_t tweak[16])
{
    memcpy(tweak, iv, 8);
    store_le32(tweak + 8, msg_counter);
    store_le32(tweak + 12, chunk_index);
}

static void build_chunk_paths(const char* output_dir, const char* mode, unsigned chunk_size,
                              char* encrypted, char* decrypted)
{
    sprintf(encrypted, "%s/aes_%d_%s_chunk%u_encrypted.txt",
            output_dir, AES_KEYLENGTH * 8, mode, chunk_size);
    sprintf(decrypted, "%s/aes_%d_%s_chunk%u_decrypted.hex",
            output_dir, AES_KEYLENGTH * 8, mode, chunk_size);
}

#if CHUNK_GCM_DEMO
#define GCM_CHUNK_AAD_LEN 8

static void make_chunk_aad(unsigned long msg_counter, unsigned chunk_index,
                           uint8_t flags, uint8_t aad[GCM_CHUNK_AAD_LEN])
{
    store_be32(aad, msg_counter);
    store_be16(aad + 4, chunk_index);
    aad[6] = flags;
    aad[7] = 0;
}

static char write_gcm_chunk_file(const uint8_t* key, const uint8_t* iv,
                                 const uint8_t* plain, size_t plain_len,
                                 const char* encrypted_path)
{
    FILE* enc = NULL;
    size_t offset = 0, cipher_len = 0;
    uint8_t aad[GCM_CHUNK_AAD_LEN], nonce[GCM_NONCE_LEN];
    uint8_t* cipher = NULL;
    unsigned chunk_index = 0;
    const unsigned long expected_counter = 1U;
    uint8_t flags = 0;

    enc = fopen(encrypted_path, "wb");
    if (!enc) return 0;

    while (offset < plain_len)
    {
        flags = offset + CHUNK_GCM_SIZE == plain_len;
        make_chunk_aad(expected_counter, chunk_index, flags, aad);
        make_gcm_nonce(iv, expected_counter, chunk_index, nonce);
        cipher_len = CHUNK_GCM_SIZE + GCM_TAG_LEN;
        cipher = alloc_bytes(cipher_len);
        if (!cipher)
        {
            fclose(enc);
            remove(encrypted_path);
            return 0;
        }

        AES_GCM_encrypt(key, nonce, aad, sizeof aad, plain + offset, CHUNK_GCM_SIZE, cipher);
        if (!write_chunk_record(enc, expected_counter, chunk_index, flags, cipher, cipher_len))
        {
            free(cipher);
            fclose(enc);
            remove(encrypted_path);
            return 0;
        }

        free(cipher);
        cipher = NULL;
        offset += CHUNK_GCM_SIZE;
        ++chunk_index;
    }
    return fclose(enc) == 0;
}

static char write_gcm_chunk_plaintext(const uint8_t* key, const uint8_t* iv,
                                      const char* encrypted_path, const char* decrypted_path)
{
    char line[192];
    FILE *in = NULL, *dec = NULL;
    size_t cipher_len = 0;
    uint8_t aad[GCM_CHUNK_AAD_LEN], nonce[GCM_NONCE_LEN];
    uint8_t *cipher = NULL, *decrypted = NULL;
    unsigned parsed_index = 0;
    const unsigned long expected_counter = 1U;
    unsigned long parsed_counter = 0;
    uint8_t parsed_flags = 0;

    in = fopen(encrypted_path, "rb");
    dec = fopen(decrypted_path, "wb");
    if (!in || !dec) goto gcm_fail;

    while (fgets(line, sizeof line, in))
    {
        if (!parse_chunk_record(line, &parsed_counter, &parsed_index, &parsed_flags, &cipher, &cipher_len))
            goto gcm_fail;
        if (parsed_counter != expected_counter || cipher_len != CHUNK_GCM_SIZE + GCM_TAG_LEN)
            goto gcm_fail;

        make_chunk_aad(parsed_counter, parsed_index, parsed_flags, aad);
        make_gcm_nonce(iv, parsed_counter, parsed_index, nonce);
        decrypted = alloc_bytes(CHUNK_GCM_SIZE);
        if (!decrypted
         || AES_GCM_decrypt(key, nonce, aad, sizeof aad, cipher, CHUNK_GCM_SIZE, decrypted)
         || !append_hex_line(dec, decrypted, CHUNK_GCM_SIZE))
            goto gcm_fail;

        free(cipher);
        free(decrypted);
        cipher = decrypted = NULL;
    }

    if (fclose(in) != 0 || fclose(dec) != 0) goto gcm_fail_closed;
    return 1;

gcm_fail:
    if (in) fclose(in);
    if (dec) fclose(dec);
    free(cipher);
    free(decrypted);
    remove(decrypted_path);
    return 0;

gcm_fail_closed:
    free(cipher);
    free(decrypted);
    remove(decrypted_path);
    return 0;
}

void run_gcm_chunk_mode(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* plain, size_t plain_len,
                        const char* output_dir)
{
    char encrypted_path[PATH_CAP], decrypted_path[PATH_CAP];
    char mode_label[24];

    sprintf(mode_label, "gcm_chunk%d", CHUNK_GCM_SIZE);
    if (plain_len % CHUNK_GCM_SIZE != 0)
    {
        printf("%-14s skipped (input size must be a multiple of %d bytes)\n",
               mode_label, CHUNK_GCM_SIZE);
        return;
    }

    build_chunk_paths(output_dir, "gcm", CHUNK_GCM_SIZE, encrypted_path, decrypted_path);
    if (!write_gcm_chunk_file(key, iv, plain, plain_len, encrypted_path)) return;
    if (!write_gcm_chunk_plaintext(key, iv, encrypted_path, decrypted_path)) return;

    printf("%-14s %s | %s\n", mode_label, encrypted_path, decrypted_path);
}
#endif

#if CHUNK_XTS_DEMO
static char write_xts_chunk_file(const uint8_t* key, const uint8_t* iv,
                                 const uint8_t* plain, size_t plain_len,
                                 const char* encrypted_path)
{
    FILE* enc = NULL;
    size_t offset = 0, cipher_len = 0;
    uint8_t tweak[16];
    uint8_t* cipher = NULL;
    unsigned chunk_index = 0;
    const unsigned long expected_counter = 1U;
    uint8_t flags = 0;

    enc = fopen(encrypted_path, "wb");
    if (!enc) return 0;

    while (offset < plain_len)
    {
        flags = offset + CHUNK_XTS_SIZE == plain_len;
        make_xts_tweak(iv, expected_counter, chunk_index, tweak);
        cipher_len = CHUNK_XTS_SIZE;
        cipher = alloc_bytes(cipher_len);
        if (!cipher || AES_XTS_encrypt(key, tweak, plain + offset, CHUNK_XTS_SIZE, cipher))
        {
            free(cipher);
            fclose(enc);
            remove(encrypted_path);
            return 0;
        }

        if (!write_chunk_record(enc, expected_counter, chunk_index, flags, cipher, cipher_len))
        {
            free(cipher);
            fclose(enc);
            remove(encrypted_path);
            return 0;
        }

        free(cipher);
        cipher = NULL;
        offset += CHUNK_XTS_SIZE;
        ++chunk_index;
    }
    return fclose(enc) == 0;
}

static char write_xts_chunk_plaintext(const uint8_t* key, const uint8_t* iv,
                                      const char* encrypted_path, const char* decrypted_path)
{
    char line[192];
    FILE *in = NULL, *dec = NULL;
    size_t cipher_len = 0;
    uint8_t tweak[16];
    uint8_t *cipher = NULL, *decrypted = NULL;
    unsigned parsed_index = 0;
    const unsigned long expected_counter = 1U;
    unsigned long parsed_counter = 0;
    uint8_t parsed_flags = 0;

    in = fopen(encrypted_path, "rb");
    dec = fopen(decrypted_path, "wb");
    if (!in || !dec) goto xts_fail;

    while (fgets(line, sizeof line, in))
    {
        if (!parse_chunk_record(line, &parsed_counter, &parsed_index, &parsed_flags, &cipher, &cipher_len))
            goto xts_fail;
        if (parsed_counter != expected_counter || cipher_len != CHUNK_XTS_SIZE)
            goto xts_fail;

        make_xts_tweak(iv, parsed_counter, parsed_index, tweak);
        decrypted = alloc_bytes(CHUNK_XTS_SIZE);
        if (!decrypted
         || AES_XTS_decrypt(key, tweak, cipher, CHUNK_XTS_SIZE, decrypted)
         || !append_hex_line(dec, decrypted, CHUNK_XTS_SIZE))
            goto xts_fail;

        free(cipher);
        free(decrypted);
        cipher = decrypted = NULL;
    }

    if (fclose(in) != 0 || fclose(dec) != 0) goto xts_fail_closed;
    return 1;

xts_fail:
    if (in) fclose(in);
    if (dec) fclose(dec);
    free(cipher);
    free(decrypted);
    remove(decrypted_path);
    return 0;

xts_fail_closed:
    free(cipher);
    free(decrypted);
    remove(decrypted_path);
    return 0;
}

void run_xts_chunk_mode(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* plain, size_t plain_len,
                        const char* output_dir)
{
    char encrypted_path[PATH_CAP], decrypted_path[PATH_CAP];
    char mode_label[24];

    sprintf(mode_label, "xts_chunk%d", CHUNK_XTS_SIZE);
    if (plain_len % CHUNK_XTS_SIZE != 0)
    {
        printf("%-14s skipped (input size must be a multiple of %d bytes)\n",
               mode_label, CHUNK_XTS_SIZE);
        return;
    }

    build_chunk_paths(output_dir, "xts", CHUNK_XTS_SIZE, encrypted_path, decrypted_path);
    if (!write_xts_chunk_file(key, iv, plain, plain_len, encrypted_path)) return;
    if (!write_xts_chunk_plaintext(key, iv, encrypted_path, decrypted_path)) return;

    printf("%-14s %s | %s\n", mode_label, encrypted_path, decrypted_path);
}
#endif

#endif
