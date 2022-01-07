#ifndef __AESNI_H__
#define __AESNI_H__

#include "aes.h"

typedef enum _AES_MODE {
    AESNI_128 = 128,
    AESNI_192 = 192,
    AESNI_256 = 256,
} AES_MODE;

typedef int (*ENCRYPT_EXPAND_KEY)(unsigned char   *key,
                                  aes_encrypt_ctx *ctx);
typedef int (*DECRYPT_EXPAND_KEY)(unsigned char   *key,
                                  aes_decrypt_ctx *ctx);
typedef int (*ENCRYPT_BLOCK)(aes_encrypt_ctx *ctx,
                             unsigned char   *input,
                             unsigned char   *output,
                             unsigned long    nblock);
typedef int (*DECRYPT_BLOCK)(aes_decrypt_ctx *ctx,
                             unsigned char   *input,
                             unsigned char   *output,
                             unsigned long    nblock);

typedef struct {
    unsigned char encctx[sizeof(aes_encrypt_ctx) + 16];
    unsigned char decctx[sizeof(aes_decrypt_ctx) + 16];
    ENCRYPT_BLOCK encrypt;
    DECRYPT_BLOCK decrypt;
} aesni_ctx;

typedef struct
{
    unsigned char encctx[sizeof(aes_encrypt_ctx) + 16];
    ENCRYPT_BLOCK encrypt;
} aesni_ctr_ctx;

#define AESNI_SUCCESS 0
#define AESNI_FAILURE 1

int has_aesni();

void no_use_aesni();

void use_aesni_if_present();

int aesni_init();

int aesni_fini();

int aesni_init_ctx(unsigned char *key,
                   AES_MODE       mode,
                   aesni_ctx     *ctx);

int aesni_init_ctr_ctx(unsigned char *key,
                       AES_MODE       mode,
                       aesni_ctr_ctx *ctx);

int aesni_encrypt_ctx(aesni_ctx     *ctx,
                      unsigned char *input,
                      unsigned char *output,
                      unsigned long  length);

int aesni_decrypt_ctx(aesni_ctx     *ctx,
                      unsigned char *input,
                      unsigned char *output,
                      unsigned long  length);

int aesni_crypt_ctr_ctx(aesni_ctr_ctx     *ctx,
                        unsigned char     *input,
                        unsigned char     *output,
                        unsigned long long offset,
                        unsigned long      length,
                        unsigned char      nonce[4]);

int aesni_encrypt(unsigned char *key,
                  AES_MODE       mode,
                  unsigned char *input,
                  unsigned char *output,
                  unsigned long  length);

int aesni_decrypt(unsigned char *key,
                  AES_MODE       mode,
                  unsigned char *input,
                  unsigned char *output,
                  unsigned long  length);

int aesni_crypt_ctr(unsigned char     *key,
                    AES_MODE           mode,
                    unsigned char     *input,
                    unsigned char     *output,
                    unsigned long long offset,
                    unsigned long      length,
                    unsigned char      nonce[4]);

#define aesni_encrypt_ctr aesni_crypt_ctr
#define aesni_decrypt_ctr aesni_crypt_ctr

#define aesni_encrypt_ctr_ctx aesni_crypt_ctr_ctx
#define aesni_decrypt_ctr_ctx aesni_crypt_ctr_ctx

#endif//__AESNI_H__
