#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define LINE (printf("%s:%d: \n\n", __FILE__, __LINE__));
#define PATH_CAP 128
#define CHUNK_SIZE 8


static char output_dir[PATH_CAP] = "../outputs";

/**
 * @brief Converts a hex string into a byte array.
 *
 * Non-hex characters in the input string are silently ignored.
 *
 * @param hex   Null-terminated hex string to convert.
 * @param bytes Output buffer that receives the decoded bytes.
 */
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

/**
 * @brief Returns the number of bytes encoded in a hex string.
 *
 * Counts only valid hex digits ('0'-'9', 'A'-'F', 'a'-'f') and
 * divides by two, since each byte is represented by two hex digits.
 *
 * @param hex Null-terminated hex string to analyse.
 * @return Number of bytes that the hex string represents.
 */
static size_t hexbytes_len(const char* hex)
{
    size_t digits = 0;

    for (; *hex; ++hex)
        if (('0' <= *hex && *hex <= '9') || ('A' <= *hex && *hex <= 'F')
         || ('a' <= *hex && *hex <= 'f')) ++digits;
    return digits / 2;
}

/**
 * @brief Builds output file paths for encrypted and decrypted results.
 *
 * Paths are written into the caller-supplied buffers using the global
 * @c output_dir, the given mode name, and the fixed key size 128.
 *
 * @param mode      Cipher mode name used in the file name (e.g. "Blowfish").
 * @param encrypted Buffer that receives the encrypted output path (at least PATH_CAP bytes).
 * @param decrypted Buffer that receives the decrypted output path (at least PATH_CAP bytes).
 */
static void build_output_paths(const char* mode, char* encrypted, char* decrypted)
{
   sprintf(encrypted, "%s/%s_%d_encrypted.hex", output_dir, mode, 128);
   sprintf(decrypted, "%s/%s_%d_decrypted.hex", output_dir, mode, 128);
}

/**
 * @brief Checks whether the file at the given path can be opened for reading.
 *
 * Opens the file in binary read mode, prints a status message, then closes it.
 *
 * @param path Null-terminated path of the file to check.
 * @return 1 if the file exists and can be opened, 0 otherwise.
 */
static char resolve_input_path(const char* path)
{

    size_t i;
    FILE* file;

        file = fopen(path, "rb");
        if (!file)
        {
            printf("Cannot open file %s\n", path);
            return 0;
        }
        else
        {
            printf("File %s found\n", path);
            fclose(file);
            return 1;
        }
    return 0;
}

/**
 * @brief Appends @p size bytes as lowercase hex followed by a newline to @p file.
 *
 * @param file Opened, writable FILE stream to write into.
 * @param data Pointer to the data to encode.
 * @param size Number of bytes to encode.
 * @return 1 on success, 0 if any write operation fails.
 */
static char append_hex_line(FILE* file, const void* data, size_t size)
{
    const uint8_t* bytes = (const uint8_t*) data;

    while (size--)
        if (fprintf(file, "%02x", *bytes++) < 0) return 0;
    return fputc('\n', file) != EOF;
}

/**
 * @brief Reads an entire text file into a newly allocated buffer.
 *
 * The caller is responsible for freeing @p *text. The buffer is
 * null-terminated, though the file may contain embedded null bytes.
 *
 * @param path Path of the file to read.
 * @param text Output pointer that receives the allocated buffer.
 * @param size Output pointer that receives the number of bytes read.
 * @return 1 on success, 0 on any I/O or allocation failure.
 */
static char read_whole_text_file(const char* path, char** text, size_t* size)
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

/**
 * @brief Loads a hex file and decodes its contents into a byte array.
 *
 * Reads the file as text, determines the byte count via hexbytes_len(),
 * allocates a buffer, and decodes the hex data into it via hex2bytes().
 * The caller is responsible for freeing @p *bytes.
 *
 * @param path  Path of the hex file to load.
 * @param bytes Output pointer that receives the allocated decoded byte buffer.
 * @param size  Output pointer that receives the number of decoded bytes.
 * @return 1 on success, 0 on any I/O or allocation failure.
 */
static char load_hex_file(const char* path, uint8_t** bytes, size_t* size)
{
    char* text = NULL;

    if (!read_whole_text_file(path, &text, size)) return 0;
    *size = hexbytes_len(text);
    *bytes = malloc(*size);
    if (!*bytes)
    {
        free(text);
        return 0;
    }
    hex2bytes(text, *bytes);
    free(text);
    return 1;
}

/**
 * @brief Writes a byte array to a file as lowercase hex, inserting a newline every 8 bytes.
 *
 * @param path Path of the output file to create or overwrite.
 * @param data Pointer to the data to encode.
 * @param size Number of bytes to encode.
 * @return 1 on success, 0 on any I/O failure.
 */
static char write_whole_hex_file(const char* path, const void* data, size_t size)
{
    const uint8_t* bytes = (const uint8_t*) data;
    FILE* file = fopen(path, "wb");
    uint32_t loop_counter = 0;
    if (!file) return 0;
    while (size--)
    {
        if (fprintf(file, "%02x", *bytes++) < 0)
        {
            fclose(file);
            return 0;
        }
        if (++loop_counter % 8 == 0)
            fputc('\n', file);
    }
    return fclose(file) == 0;
}

/**
 * @brief Writes a byte array to a file as lowercase hex in 8-byte chunks, flushing after each chunk.
 *
 * Each 8-byte chunk is written on its own line. The stream is flushed
 * after every line to ensure partial output is visible on failure.
 *
 * @param path Path of the output file to create or overwrite.
 * @param data Pointer to the data to encode.
 * @param size Total number of bytes to encode (should be a multiple of 8).
 * @return 1 on success, 0 on any I/O failure.
 */
static char write_8byte_hex_file(const char* path, const void* data, size_t size)
{
    const uint8_t* bytes = (const uint8_t*) data;
    FILE* file = fopen(path, "wb");
    uint32_t loop_counter = 0;
    if (!file) return 0;
    for (size_t file_index = 0; file_index < size; file_index += 8)
    {
        int chunk_size = 8;
        while (chunk_size--)
        {
            if (fprintf(file, "%02x", *bytes++) < 0)
            {
                fclose(file);
                return 0;
            }
            if (++loop_counter % 8 == 0)
            {
                fputc('\n', file);
                fflush(file);
            }
        }
    }
    return fclose(file) == 0;
}

/**
 * @brief Runs a Blowfish encrypt-then-decrypt demo on plaintext data.
 *
 * Encrypts @p plain in CHUNK_SIZE-byte blocks, writes the ciphertext to a
 * hex file, reloads that file, decrypts each block, and writes the result
 * to a second hex file. Paths are derived from @p mode via build_output_paths().
 *
 * @param mode      Label used to build the output file names (e.g. "Blowfish").
 * @param plain     Pointer to the plaintext byte array.
 * @param plain_len Length of the plaintext in bytes (must be a multiple of CHUNK_SIZE).
 */
static void run_blowfish_mode(const char* mode, const uint8_t* plain, size_t plain_len)
{
    char encrypted_path[PATH_CAP], decrypted_path[PATH_CAP];
    /*  */
    uint8_t *buffer_8byte = NULL;
    buffer_8byte = malloc(CHUNK_SIZE);

    uint8_t *encrypted_8byte = NULL;
    /* */
    FILE *ptr_encrypted_file = NULL;

    build_output_paths(mode, encrypted_path, decrypted_path);
    /**/
    encrypted_8byte = malloc(CHUNK_SIZE);
    /**ENCRYPTION**/
    ptr_encrypted_file = fopen(encrypted_path, "wb");
    if (!ptr_encrypted_file)
    {
        printf("Failed to open encrypted file for writing\n");
        goto cleanup;
    }
    for (size_t i = 0; i < plain_len; i += CHUNK_SIZE) {
        memcpy(buffer_8byte, plain + i, CHUNK_SIZE);
        /*
        enctypt_fn;buffer_8byte ---> encrypted_8byte
        */
        if (!append_hex_line(ptr_encrypted_file, buffer_8byte, CHUNK_SIZE))
        {
            printf("Failed to write encrypted file\n");
            goto cleanup;
        }
    }
    fclose(ptr_encrypted_file);
    /****/


    /**DECRYPTION**/
    FILE *ptr_decrypted_file = NULL;
    uint8_t *encrypted_hex_file = NULL;
    uint8_t *decrypted_8byte = NULL;
    size_t encrypted_hex_file_len = 0;

    decrypted_8byte = malloc(CHUNK_SIZE);
    encrypted_hex_file = malloc(plain_len);

    if (!load_hex_file(encrypted_path, &encrypted_hex_file, &encrypted_hex_file_len))
        if(encrypted_hex_file_len != plain_len)
            goto cleanup;

    ptr_decrypted_file = fopen(decrypted_path, "wb");
    if (!ptr_decrypted_file)
    {
        printf("Failed to open decrypted file for writing\n");
        goto cleanup;
    }

    for (size_t i = 0; i < encrypted_hex_file_len; i += CHUNK_SIZE)
    {
        memcpy(buffer_8byte, encrypted_hex_file + i, CHUNK_SIZE);
        /*
            decrypt_fn;buffer_8byte ---> decrypted_8byte
        */
        if (!append_hex_line(ptr_decrypted_file, buffer_8byte, CHUNK_SIZE))
        {
            printf("Failed to write encrypted file\n");
            goto cleanup;
        }
    }
    printf("%-14s %s | %s\n", mode, encrypted_path, decrypted_path);

cleanup:
    free(encrypted_hex_file);
    free(decrypted_8byte);
}

/**
 * @brief Loads a hex input file and runs the Blowfish demo on its contents.
 *
 * Verifies the file exists, loads it as a hex byte array, validates that its
 * length is a multiple of 8 (required by Blowfish), then delegates to
 * run_blowfish_mode().
 *
 * @param path Path to the input hex file (e.g. "../input/demo_hex.txt").
 */
static void run_blowfish(const char *path)
{
    uint8_t* plain = NULL;
    size_t plain_len = 0;

    if (!resolve_input_path(path) || !load_hex_file(path, &plain, &plain_len))
    {
        printf("File mode demo : cannot read input/demo_hex.txt\n");
        return;
    }
    printf("File input     %s (%u bytes)\n", path, (unsigned) plain_len);
    if(plain_len % 8 != 0)
    {
        printf("File mode demo : input length must be a multiple of 8 bytes for Blowfish\n");
        free(plain);
        return;
    }
    else
    {
        run_blowfish_mode("Blowfish", plain, plain_len);
    }
}

/**
 * @brief Program entry point.
 *
 * Runs the file-based encryption demo on the default input file and
 * prints a build-timestamp banner on exit.
 *
 * @return 0 on success.
 */
int main(void)
{

    run_blowfish("../input/demo_hex.txt");

    printf("%s %s File Encryption Demo\n", __DATE__, __TIME__);
    return 0;

}