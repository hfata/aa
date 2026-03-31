/*
 ==============================================================================
 Name        : main.c
 Description : file-based encryption/decryption demo for enabled uAES modes
 ==============================================================================
 */

#include "micro_aes.h"
#include "chunk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_CAP 128

static const char
    *IV_HEX   = "8EA2B7CA516745BF EAfc49904b496089",
    *KEY_HEX  = "279fb74a7572135e 8f9b8ef6d1eee003 69c4e0d86a7b0430 d8cdb78070b4c55a",
    *KEY2_HEX = "0011223344556677 8899AABBCCDDEEFF 0001020304050607 08090A0B0C0D0E0F",
    *AAD_HEX  = "0001020304050607 08090A0B0C0D0E0F 1011121314151617 18191A1B1C1D1E1F";

static char output_dir[PATH_CAP] = "./outputs";

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

static void build_output_paths(const char* mode, char* encrypted, char* decrypted)
{
    sprintf(encrypted, "%s/aes_%d_%s_encrypted.hex", output_dir, AES_KEYLENGTH * 8, mode);
    sprintf(decrypted, "%s/aes_%d_%s_decrypted.hex", output_dir, AES_KEYLENGTH * 8, mode);
}

static char resolve_input_path(char* path)
{
    static const char* const candidates[] = {
        "./input/demo_hex.txt",
        "../input/demo_hex.txt",
    };
    size_t i;
    FILE* file;

    for (i = 0; i < sizeof candidates / sizeof *candidates; ++i)
    {
        strcpy(path, candidates[i]);
        file = fopen(path, "rb");
        if (!file) continue;
        fclose(file);
        strcpy(output_dir, i == 0 ? "./outputs" : "../outputs");
        return 1;
    }
    return 0;
}

static char read_text_file(const char* path, char** text, size_t* size)
{
    FILE* file = fopen(path, "rb");
    long len;

    if (!file) return 0;
    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return 0; }
    len = ftell(file);
    if (len < 0 || fseek(file, 0, SEEK_SET) != 0) { fclose(file); return 0; }

    *text = malloc((size_t) len + 1);
    if (!*text) { fclose(file); return 0; }

    *size = fread(*text, 1, (size_t) len, file);
    fclose(file);
    (*text)[*size] = '\0';
    return 1;
}

static char load_hex_file(const char* path, uint8_t** bytes, size_t* size)
{
    char* text = NULL;

    if (!read_text_file(path, &text, size)) return 0;
    *size = hexbytes_len(text);
    *bytes = alloc_bytes(*size);
    if (!*bytes)
    {
        free(text);
        return 0;
    }
    hex2bytes(text, *bytes);
    free(text);
    return 1;
}

static char write_hex_file(const char* path, const void* data, size_t size)
{
    const uint8_t* bytes = (const uint8_t*) data;
    FILE* file = fopen(path, "wb");

    if (!file) return 0;
    while (size--)
        if (fprintf(file, "%02x", *bytes++) < 0)
        {
            fclose(file);
            return 0;
        }
    fputc('\n', file);
    return fclose(file) == 0;
}

typedef char (*file_mode_encrypt_fn)(const uint8_t*, const uint8_t*,
                                     const void*, size_t, void*);
typedef char (*file_mode_decrypt_fn)(const uint8_t*, const uint8_t*,
                                     const void*, size_t, void*);
typedef void (*file_aead_encrypt_fn)(const uint8_t*, const uint8_t*,
                                     const void*, size_t, const void*, size_t, void*);
typedef char (*file_aead_decrypt_fn)(const uint8_t*, const uint8_t*,
                                     const void*, size_t, const void*, size_t, void*);

static char ecb_size(size_t plain_len, size_t* cipher_len)
{
    *cipher_len = plain_len + ((16 - plain_len % 16) & 15);
    return 1;
}

static char cbc_size(size_t plain_len, size_t* cipher_len)
{
#if CTS
    if (plain_len < 16) return 0;
    *cipher_len = plain_len;
#else
    *cipher_len = plain_len + ((16 - plain_len % 16) & 15);
#endif
    return 1;
}

static char stream_size(size_t plain_len, size_t* cipher_len)
{
    *cipher_len = plain_len;
    return 1;
}

static char xts_size(size_t plain_len, size_t* cipher_len)
{
    if (plain_len < 16) return 0;
    *cipher_len = plain_len;
    return 1;
}

#if ECB
static char ecb_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    (void) iv;
    AES_ECB_encrypt(key, input, size, output);
    return 0;
}

static char ecb_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    (void) iv;
    return AES_ECB_decrypt(key, input, size, output);
}
#endif

#if CBC
static char cbc_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    return AES_CBC_encrypt(key, iv, input, size, output);
}

static char cbc_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    return AES_CBC_decrypt(key, iv, input, size, output);
}
#endif

#if CFB
static char cfb_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    AES_CFB_encrypt(key, iv, input, size, output);
    return 0;
}

static char cfb_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    AES_CFB_decrypt(key, iv, input, size, output);
    return 0;
}
#endif

#if OFB
static char ofb_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    AES_OFB_encrypt(key, iv, input, size, output);
    return 0;
}

static char ofb_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    AES_OFB_decrypt(key, iv, input, size, output);
    return 0;
}
#endif

#if CTR_NA
static char ctr_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    AES_CTR_encrypt(key, iv, input, size, output);
    return 0;
}

static char ctr_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    AES_CTR_decrypt(key, iv, input, size, output);
    return 0;
}
#endif

#if XTS
static char xts_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    return AES_XTS_encrypt(key, iv, input, size, output);
}

static char xts_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* input, size_t size, void* output)
{
    return AES_XTS_decrypt(key, iv, input, size, output);
}
#endif

#if GCM
static void gcm_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    AES_GCM_encrypt(key, iv, aad, aad_len, input, size, output);
}

static char gcm_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    return AES_GCM_decrypt(key, iv, aad, aad_len, input, size, output);
}
#endif

#if CCM
static void ccm_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    AES_CCM_encrypt(key, iv, aad, aad_len, input, size, output);
}

static char ccm_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    return AES_CCM_decrypt(key, iv, aad, aad_len, input, size, output);
}
#endif

#if OCB
static void ocb_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    AES_OCB_encrypt(key, iv, aad, aad_len, input, size, output);
}

static char ocb_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    return AES_OCB_decrypt(key, iv, aad, aad_len, input, size, output);
}
#endif

#if EAX && !EAXP
static void eax_encrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    AES_EAX_encrypt(key, iv, aad, aad_len, input, size, output);
}

static char eax_decrypt_file(const uint8_t* key, const uint8_t* iv,
                             const void* aad, size_t aad_len,
                             const void* input, size_t size, void* output)
{
    return AES_EAX_decrypt(key, iv, aad, aad_len, input, size, output);
}
#endif

#if GCM_SIV
static void gcmsiv_encrypt_file(const uint8_t* key, const uint8_t* iv,
                                const void* aad, size_t aad_len,
                                const void* input, size_t size, void* output)
{
    GCM_SIV_encrypt(key, iv, aad, aad_len, input, size, output);
}

static char gcmsiv_decrypt_file(const uint8_t* key, const uint8_t* iv,
                                const void* aad, size_t aad_len,
                                const void* input, size_t size, void* output)
{
    return GCM_SIV_decrypt(key, iv, aad, aad_len, input, size, output);
}
#endif

static void run_basic_mode(const char* mode,
                           const uint8_t* key, const uint8_t* iv,
                           const uint8_t* plain, size_t plain_len,
                           char (*size_of_cipher)(size_t, size_t*),
                           file_mode_encrypt_fn encrypt_fn,
                           file_mode_decrypt_fn decrypt_fn)
{
    char encrypted_path[PATH_CAP], decrypted_path[PATH_CAP];
    uint8_t *cipher = NULL, *loaded = NULL, *decrypted = NULL;
    size_t cipher_len = 0, loaded_len = 0;

    if (!size_of_cipher(plain_len, &cipher_len))
    {
        printf("%-14s skipped\n", mode);
        return;
    }

    build_output_paths(mode, encrypted_path, decrypted_path);
    cipher = alloc_bytes(cipher_len);
    decrypted = alloc_bytes(plain_len);
    if (!cipher || !decrypted) goto cleanup;

    if (encrypt_fn(key, iv, plain, plain_len, cipher)) goto cleanup;
    if (!write_hex_file(encrypted_path, cipher, cipher_len)) goto cleanup;
    if (!load_hex_file(encrypted_path, &loaded, &loaded_len) || loaded_len != cipher_len)
        goto cleanup;
    if (decrypt_fn(key, iv, loaded, cipher_len, decrypted)) goto cleanup;
    if (!write_hex_file(decrypted_path, decrypted, plain_len)) goto cleanup;

    printf("%-14s %s | %s\n", mode, encrypted_path, decrypted_path);

cleanup:
    free(cipher);
    free(loaded);
    free(decrypted);
}

static void run_aead_mode(const char* mode,
                          const uint8_t* key, const uint8_t* iv,
                          const void* aad, size_t aad_len,
                          const uint8_t* plain, size_t plain_len, size_t tag_len,
                          file_aead_encrypt_fn encrypt_fn,
                          file_aead_decrypt_fn decrypt_fn)
{
    char encrypted_path[PATH_CAP], decrypted_path[PATH_CAP];
    uint8_t *cipher = NULL, *loaded = NULL, *decrypted = NULL;
    size_t cipher_len = plain_len + tag_len, loaded_len = 0;

    build_output_paths(mode, encrypted_path, decrypted_path);
    cipher = alloc_bytes(cipher_len);
    decrypted = alloc_bytes(plain_len);
    if (!cipher || !decrypted) goto cleanup;

    encrypt_fn(key, iv, aad, aad_len, plain, plain_len, cipher);
    if (!write_hex_file(encrypted_path, cipher, cipher_len)) goto cleanup;
    if (!load_hex_file(encrypted_path, &loaded, &loaded_len) || loaded_len != cipher_len)
        goto cleanup;
    if (decrypt_fn(key, iv, aad, aad_len, loaded, plain_len, decrypted)) goto cleanup;
    if (!write_hex_file(decrypted_path, decrypted, plain_len)) goto cleanup;

    printf("%-14s %s | %s\n", mode, encrypted_path, decrypted_path);

cleanup:
    free(cipher);
    free(loaded);
    free(decrypted);
}

#if SIV
static void run_siv_mode(const uint8_t* key, const void* aad, size_t aad_len,
                         const uint8_t* plain, size_t plain_len)
{
    char encrypted_path[PATH_CAP], decrypted_path[PATH_CAP];
    uint8_t *bundle = NULL, *loaded = NULL, *decrypted = NULL;
    size_t bundle_len = plain_len + 16, loaded_len = 0;

    build_output_paths("siv", encrypted_path, decrypted_path);
    bundle = alloc_bytes(bundle_len);
    decrypted = alloc_bytes(plain_len);
    if (!bundle || !decrypted) goto cleanup;

    AES_SIV_encrypt(key, aad, aad_len, plain, plain_len, bundle, bundle + 16);
    if (!write_hex_file(encrypted_path, bundle, bundle_len)) goto cleanup;
    if (!load_hex_file(encrypted_path, &loaded, &loaded_len) || loaded_len != bundle_len)
        goto cleanup;
    if (AES_SIV_decrypt(key, loaded, aad, aad_len, loaded + 16, plain_len, decrypted))
        goto cleanup;
    if (!write_hex_file(decrypted_path, decrypted, plain_len)) goto cleanup;

    printf("%-14s %s | %s\n", "siv", encrypted_path, decrypted_path);

cleanup:
    free(bundle);
    free(loaded);
    free(decrypted);
}
#endif

static void run_file_demos(const uint8_t* key, const uint8_t* iv,
                           const void* aad, size_t aad_len)
{
    char input_path[PATH_CAP];
    uint8_t* plain = NULL;
    size_t plain_len = 0;

    if (!resolve_input_path(input_path) || !load_hex_file(input_path, &plain, &plain_len))
    {
        printf("File mode demo : cannot read input/demo_hex.txt\n");
        return;
    }

    printf("File input     %s (%u bytes)\n", input_path, (unsigned) plain_len);

#if ECB
    run_basic_mode("ecb", key, iv, plain, plain_len, ecb_size, ecb_encrypt_file, ecb_decrypt_file);
#endif
#if CBC
    run_basic_mode("cbc", key, iv, plain, plain_len, cbc_size, cbc_encrypt_file, cbc_decrypt_file);
#endif
#if CFB
    run_basic_mode("cfb", key, iv, plain, plain_len, stream_size, cfb_encrypt_file, cfb_decrypt_file);
#endif
#if OFB
    run_basic_mode("ofb", key, iv, plain, plain_len, stream_size, ofb_encrypt_file, ofb_decrypt_file);
#endif
#if CTR_NA
    run_basic_mode("ctr", key, iv, plain, plain_len, stream_size, ctr_encrypt_file, ctr_decrypt_file);
#endif
#if XTS
    run_basic_mode("xts", key, iv, plain, plain_len, xts_size, xts_encrypt_file, xts_decrypt_file);
#if CHUNK_XTS_DEMO
    run_xts_chunk_mode(key, iv, plain, plain_len, output_dir);
#endif
#endif
#if GCM && AES___ != 192
    run_aead_mode("gcm", key, iv, aad, aad_len, plain, plain_len,
                  GCM_TAG_LEN, gcm_encrypt_file, gcm_decrypt_file);
#if CHUNK_GCM_DEMO
    run_gcm_chunk_mode(key, iv, plain, plain_len, output_dir);
#endif
#endif
#if CCM && AES___ == 128
    run_aead_mode("ccm", key, iv, aad, aad_len, plain, plain_len,
                  CCM_TAG_LEN, ccm_encrypt_file, ccm_decrypt_file);
#endif
#if OCB && AES___ == 128
    run_aead_mode("ocb", key, iv, aad, aad_len, plain, plain_len,
                  OCB_TAG_LEN, ocb_encrypt_file, ocb_decrypt_file);
#endif
#if EAX && AES___ == 128 && !EAXP
    run_aead_mode("eax", key, iv, aad, aad_len, plain, plain_len,
                  EAX_TAG_LEN, eax_encrypt_file, eax_decrypt_file);
#endif
#if GCM_SIV && AES___ == 128
    run_aead_mode("gcmsiv", key, iv, aad, aad_len, plain, plain_len,
                  SIVGCM_TAG_LEN, gcmsiv_encrypt_file, gcmsiv_decrypt_file);
#endif
#if SIV && AES___ == 128
    run_siv_mode(key, aad, aad_len, plain, plain_len);
#endif

    free(plain);
}

int main(void)
{
#if MICRO_RJNDL
    printf("File demo needs at least one block or AEAD mode enabled.\n");
    return 0;
#else
    uint8_t iv[16], keys[64], aad[32];

    hex2bytes(IV_HEX, iv);
    hex2bytes(KEY_HEX, keys);
    hex2bytes(KEY2_HEX, keys + 32);
    hex2bytes(AAD_HEX, aad);

    printf("%s %s File Encryption Demo\n", __DATE__, __TIME__);
    run_file_demos(keys, iv, aad, sizeof aad);
    return 0;
#endif
}
