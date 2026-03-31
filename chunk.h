#ifndef CHUNK8_DEMO_H_
#define CHUNK8_DEMO_H_

#include "micro_aes.h"
#include <stddef.h>
#include <stdint.h>

#ifndef CHUNK_GCM_DEMO
#define CHUNK_GCM_DEMO 0
#endif

#ifndef CHUNK_GCM_SIZE
#define CHUNK_GCM_SIZE 8
#endif

#if CHUNK_GCM_SIZE != 8 && CHUNK_GCM_SIZE != 16 && CHUNK_GCM_SIZE != 32
#error CHUNK_GCM_SIZE must be 8, 16, or 32
#endif

#ifndef CHUNK_XTS_DEMO
#define CHUNK_XTS_DEMO 1
#endif

#ifndef CHUNK_XTS_SIZE
#define CHUNK_XTS_SIZE 16
#endif

#if CHUNK_XTS_SIZE != 16 && CHUNK_XTS_SIZE != 32
#error CHUNK_XTS_SIZE must be 16 or 32
#endif

#if CHUNK_XTS_DEMO && !XTS
#error CHUNK_XTS_DEMO requires XTS to be enabled
#endif

#if CHUNK_GCM_DEMO
void run_gcm_chunk_mode(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* plain, size_t plain_len,
                        const char* output_dir);
#endif

#if CHUNK_XTS_DEMO
void run_xts_chunk_mode(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* plain, size_t plain_len,
                        const char* output_dir);
#endif

#endif
