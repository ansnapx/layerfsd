#include "aesni.h"
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>
#include "aes.h"
#include "iaes_asm_interface.h"

#pragma intrinsic(__cpuid)

#define AES_INSTRCTIONS_CPUID_BIT (1<<25)

static int inited = 0;

static int no_ni = 0; // don't use aes-ni
static int aes_ni_present = 0;

int has_aesni()
{
    return aes_ni_present;
}

int check_cpu_aesni()
{
    unsigned int cpuid_results[4] /* eax/ebx/ecx/edx */;

    __cpuid(cpuid_results, 0);
    if (cpuid_results[0] < 1)
        return 0;

/*
 * AMD CPU
 *
 *
 * CPUID Fn0000_0000_EBX 6874_7541h "htuA"
 * CPUID Fn0000_0000_EDX 6974_6E65h "itne"
 * CPUID Fn0000_0000_ECX 444D_4163h "DMAc"
 */

/*
 * Intel CPU
 *
 *      MSB         LSB
 * EBX = 'u' 'n' 'e' 'G'
 * EDX = 'I' 'e' 'n' 'i'
 * ECX = 'l' 'e' 't' 'n'
 */

    /* we need support both Intel and AMD, maybe other vendors */
    if ((memcmp((unsigned char *)&cpuid_results[1], "Genu", 4) != 0 ||
         memcmp((unsigned char *)&cpuid_results[3], "ineI", 4) != 0 ||
         memcmp((unsigned char *)&cpuid_results[2], "ntel", 4) != 0) &&
        (memcmp((unsigned char *)&cpuid_results[1], "Auth", 4) != 0 ||
         memcmp((unsigned char *)&cpuid_results[3], "enit", 4) != 0 ||
         memcmp((unsigned char *)&cpuid_results[2], "cAMD", 4) != 0))
        return 0;

    memset(cpuid_results, 0, sizeof(cpuid_results));
    __cpuid(cpuid_results, 1);
    if (cpuid_results[2] & AES_INSTRCTIONS_CPUID_BIT)
        return 1;

    return 0;
}

void no_use_aesni()
{
    no_ni = 1;
}

void use_aesni_if_present()
{
    no_ni = 0;
}

int aesni_init()
{
    if (inited)
        return AESNI_SUCCESS;

    /* whether current cpu supports hardware AES_NI */
    aes_ni_present = check_cpu_aesni();

    /* initialize AES lib */
    aes_init();

    inited = 1;

    return AESNI_SUCCESS;
}

int aesni_fini()
{
    if (!inited)
        return AESNI_SUCCESS;

    inited = 0;

    return AESNI_SUCCESS;
}

__inline
int aesni_encrypt_key128_ni(unsigned char   *key,
                            aes_encrypt_ctx *ctx)
{
    iEncExpandKey128(key, (unsigned char *)ctx->ks);
    return AESNI_SUCCESS;
}

__inline
int aesni_encrypt_key192_ni(unsigned char   *key,
                            aes_encrypt_ctx *ctx)
{
    iEncExpandKey192(key, (unsigned char *)ctx->ks);
    return AESNI_SUCCESS;
}

__inline
int aesni_encrypt_key256_ni(unsigned char   *key,
                            aes_encrypt_ctx *ctx)
{
    iEncExpandKey256(key, (unsigned char *)ctx->ks);
    return AESNI_SUCCESS;
}

__inline
int aesni_encrypt_key128_no(unsigned char   *key,
                            aes_encrypt_ctx *ctx)
{
    return aes_encrypt_key128(key, ctx);
}

__inline
int aesni_encrypt_key192_no(unsigned char   *key,
                            aes_encrypt_ctx *ctx)
{
    return aes_encrypt_key192(key, ctx);
}

__inline
int aesni_encrypt_key256_no(unsigned char   *key,
                            aes_encrypt_ctx *ctx)
{
    return aes_encrypt_key256(key, ctx);
}

__inline
int aesni_decrypt_key128_ni(unsigned char   *key,
                            aes_decrypt_ctx *ctx)
{
    iDecExpandKey128(key, (unsigned char *)ctx->ks);
    return AESNI_SUCCESS;
}

__inline
int aesni_decrypt_key192_ni(unsigned char   *key,
                            aes_decrypt_ctx *ctx)
{
    iDecExpandKey192(key, (unsigned char *)ctx->ks);
    return AESNI_SUCCESS;
}

__inline
int aesni_decrypt_key256_ni(unsigned char   *key,
                            aes_decrypt_ctx *ctx)
{
    iDecExpandKey256(key, (unsigned char *)ctx->ks);
    return AESNI_SUCCESS;
}

__inline
int aesni_decrypt_key128_no(unsigned char   *key,
                            aes_decrypt_ctx *ctx)
{
    return aes_decrypt_key128(key, ctx);
}

__inline
int aesni_decrypt_key192_no(unsigned char   *key,
                            aes_decrypt_ctx *ctx)
{
    return aes_decrypt_key192(key, ctx);
}

__inline
int aesni_decrypt_key256_no(unsigned char   *key,
                            aes_decrypt_ctx *ctx)
{
    return aes_decrypt_key256(key, ctx);
}

__inline
int aesni_encrypt128_ni(aes_encrypt_ctx *ctx,
                        unsigned char   *input,
                        unsigned char   *output,
                        unsigned long    nblock)
{
    sAesData aesdata;    
    
    aesdata.in_block = input;
    aesdata.out_block = output;
    aesdata.expanded_key = (unsigned char *)ctx->ks;
    aesdata.num_blocks = nblock;

    iEnc128(&aesdata);

    return AESNI_SUCCESS;
}

__inline
int aesni_encrypt192_ni(aes_encrypt_ctx *ctx,
                        unsigned char   *input,
                        unsigned char   *output,
                        unsigned long    nblock)
{
    sAesData aesdata;    
    
    aesdata.in_block = input;
    aesdata.out_block = output;
    aesdata.expanded_key = (unsigned char *)ctx->ks;
    aesdata.num_blocks = nblock;

    iEnc192(&aesdata);

    return AESNI_SUCCESS;
}

__inline
int aesni_encrypt256_ni(aes_encrypt_ctx *ctx,
                        unsigned char   *input,
                        unsigned char   *output,
                        unsigned long    nblock)
{
    sAesData aesdata;    
    
    aesdata.in_block = input;
    aesdata.out_block = output;
    aesdata.expanded_key = (unsigned char *)ctx->ks;
    aesdata.num_blocks = nblock;

    iEnc256(&aesdata);

    return AESNI_SUCCESS;
}

__inline
int aesni_encrypt_no(aes_encrypt_ctx *ctx,
                     unsigned char   *input,
                     unsigned char   *output,
                     unsigned long    nblock)
{
    int ret;

    while (nblock-- > 0)
    {
        ret = aes_encrypt(input, output, ctx);

        if (EXIT_SUCCESS != ret)
            return AESNI_FAILURE;

        input  += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
    }

    return AESNI_SUCCESS;
}

#define aesni_encrypt128_no aesni_encrypt_no
#define aesni_encrypt192_no aesni_encrypt_no
#define aesni_encrypt256_no aesni_encrypt_no

__inline
int aesni_decrypt128_ni(aes_decrypt_ctx *ctx,
                        unsigned char   *input,
                        unsigned char   *output,
                        unsigned long    nblock)
{
    sAesData aesdata;    
    
    aesdata.in_block = input;
    aesdata.out_block = output;
    aesdata.expanded_key = (unsigned char *)ctx->ks;
    aesdata.num_blocks = nblock;

    iDec128(&aesdata);

    return AESNI_SUCCESS;
}

__inline
int aesni_decrypt192_ni(aes_decrypt_ctx *ctx,
                        unsigned char   *input,
                        unsigned char   *output,
                        unsigned long    nblock)
{
    sAesData aesdata;    
    
    aesdata.in_block = input;
    aesdata.out_block = output;
    aesdata.expanded_key = (unsigned char *)ctx->ks;
    aesdata.num_blocks = nblock;

    iDec192(&aesdata);

    return AESNI_SUCCESS;
}

__inline
int aesni_decrypt256_ni(aes_decrypt_ctx *ctx,
                        unsigned char   *input,
                        unsigned char   *output,
                        unsigned long    nblock)
{
    sAesData aesdata;    
    
    aesdata.in_block = input;
    aesdata.out_block = output;
    aesdata.expanded_key = (unsigned char *)ctx->ks;
    aesdata.num_blocks = nblock;

    iDec256(&aesdata);

    return AESNI_SUCCESS;
}

__inline
int aesni_decrypt_no(aes_decrypt_ctx *ctx,
                     unsigned char   *input,
                     unsigned char   *output,
                     unsigned long    nblock)
{
    int ret;

    while (nblock-- > 0)
    {
        ret = aes_decrypt(input, output, ctx);

        if (EXIT_SUCCESS != ret)
            return AESNI_FAILURE;

        input  += AES_BLOCK_SIZE;
        output += AES_BLOCK_SIZE;
    }

    return AESNI_SUCCESS;
}

#define aesni_decrypt128_no aesni_decrypt_no
#define aesni_decrypt192_no aesni_decrypt_no
#define aesni_decrypt256_no aesni_decrypt_no

__inline
aes_encrypt_ctx*
aesni_get_enc_ctx(aesni_ctx *ctx)
{
    return (aes_encrypt_ctx *)(ALIGN_CEIL(ctx->encctx, 16));
}

__inline
aes_decrypt_ctx*
aesni_get_dec_ctx(aesni_ctx *ctx)
{
    return (aes_decrypt_ctx *)(ALIGN_CEIL(ctx->decctx, 16));
}

__inline
aes_encrypt_ctx*
aesni_get_ctr_enc_ctx(aesni_ctr_ctx *ctx)
{
    return (aes_encrypt_ctx *)(ALIGN_CEIL(ctx->encctx, 16));
}

int aesni_init_ctx(unsigned char *key,
                   AES_MODE       mode,
                   aesni_ctx     *ctx)
{
    int ret;

    if (has_aesni() && !no_ni) {
        switch (mode) {
            case AESNI_128:
                ret = aesni_encrypt_key128_ni(key, aesni_get_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ret = aesni_decrypt_key128_ni(key, aesni_get_dec_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt128_ni;
                ctx->decrypt = aesni_decrypt128_ni;
                break;
            case AESNI_192:
                ret = aesni_encrypt_key192_ni(key, aesni_get_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ret = aesni_decrypt_key192_ni(key, aesni_get_dec_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt192_ni;
                ctx->decrypt = aesni_decrypt192_ni;
                break;
            case AESNI_256:
                ret = aesni_encrypt_key256_ni(key, aesni_get_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ret = aesni_decrypt_key256_ni(key, aesni_get_dec_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt256_ni;
                ctx->decrypt = aesni_decrypt256_ni;
                break;
            default:
                return AESNI_FAILURE;
        }
    } else {
        switch (mode) {
            case AESNI_128:
                ret = aesni_encrypt_key128_no(key, aesni_get_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ret = aesni_decrypt_key128_no(key, aesni_get_dec_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt128_no;
                ctx->decrypt = aesni_decrypt192_no;
                break;
            case AESNI_192:
                ret = aesni_encrypt_key192_no(key, aesni_get_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ret = aesni_decrypt_key192_no(key, aesni_get_dec_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt192_no;
                ctx->decrypt = aesni_decrypt192_no;
                break;
            case AESNI_256:
                ret = aesni_encrypt_key256_no(key, aesni_get_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ret = aesni_decrypt_key256_no(key, aesni_get_dec_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt256_no;
                ctx->decrypt = aesni_decrypt256_no;
                break;
            default:
                return AESNI_FAILURE;
        }
    }

    return AESNI_SUCCESS;
}

int aesni_init_ctr_ctx(unsigned char *key,
                       AES_MODE       mode,
                       aesni_ctr_ctx *ctx)
{
    int ret;

    if (has_aesni() && !no_ni) {
        switch (mode) {
            case AESNI_128:
                ret = aesni_encrypt_key128_ni(key, aesni_get_ctr_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt128_ni;
                break;
            case AESNI_192:
                ret = aesni_encrypt_key192_ni(key, aesni_get_ctr_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt192_ni;
                break;
            case AESNI_256:
                ret = aesni_encrypt_key256_ni(key, aesni_get_ctr_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt256_ni;
                break;
            default:
                return AESNI_FAILURE;
        }
    } else {
        switch (mode) {
            case AESNI_128:
                ret = aesni_encrypt_key128_no(key, aesni_get_ctr_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt128_no;
                break;
            case AESNI_192:
                ret = aesni_encrypt_key192_no(key, aesni_get_ctr_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt192_no;
                break;
            case AESNI_256:
                ret = aesni_encrypt_key256_no(key, aesni_get_ctr_enc_ctx(ctx));
                if (AESNI_SUCCESS != ret)
                    return ret;
                ctx->encrypt = aesni_encrypt256_no;
                break;
            default:
                return AESNI_FAILURE;
        }
    }

    return AESNI_SUCCESS;

}

int aesni_encrypt_ctx(aesni_ctx     *ctx,
                      unsigned char *input,
                      unsigned char *output,
                      unsigned long  length)
{
    if ((length & (AES_BLOCK_SIZE - 1)) != 0)
        return AESNI_FAILURE;

    return ctx->encrypt(aesni_get_enc_ctx(ctx), input, output, length / AES_BLOCK_SIZE);
}

int aesni_decrypt_ctx(aesni_ctx     *ctx,
                      unsigned char *input,
                      unsigned char *output,
                      unsigned long  length)
{
    if ((length & (AES_BLOCK_SIZE - 1)) != 0)
        return AESNI_FAILURE;

    return ctx->decrypt(aesni_get_dec_ctx(ctx), input, output, length / AES_BLOCK_SIZE);
}

typedef union {
    unsigned char i8[AES_BLOCK_SIZE];
    __m128i       i128;
} AES_BLOCK;

static __inline void make_ctr_blk(AES_BLOCK *ctr_blk, int num, 
                                  unsigned long long offset, unsigned char nonce[4])
{
    int i;
    for (i = 0; i < num; i++) {
        *(uint64_t*)(ctr_blk + i)->i8 = offset + i * AES_BLOCK_SIZE;
        if (nonce) {
            *(uint32_t*)((ctr_blk + i)->i8 + 8)  = *(uint32_t*)nonce;
            *(uint32_t*)((ctr_blk + i)->i8 + 12) = *(uint32_t*)nonce;
        }
    }
}

#define BLOCK_NUM 4

int aesni_crypt_ctr_ctx(aesni_ctr_ctx     *ctx,
                        unsigned char     *input,
                        unsigned char     *output,
                        unsigned long long offset,
                        unsigned long      length,
                        unsigned char      nonce[4])
{
    int ret;
    AES_BLOCK block[BLOCK_NUM];
    unsigned long long aligned_offset;
    unsigned char i, j, k, l = 0;    
    __m128i a, b;

    while (length) {
        aligned_offset = offset & (~((unsigned long long)AES_BLOCK_SIZE - 1));
        if (l == 0) {
            make_ctr_blk(block, BLOCK_NUM, aligned_offset, nonce);
            ret = ctx->encrypt(aesni_get_ctr_enc_ctx(ctx), (unsigned char*)block, (unsigned char*)block, BLOCK_NUM);
            if (AESNI_SUCCESS != ret)
                return ret;
        }

        i = offset & (AES_BLOCK_SIZE - 1); /* offset in block */
        j = i + length > AES_BLOCK_SIZE ? (AES_BLOCK_SIZE - i) : (unsigned char)length; /* length in block */
        if ((0 == i) && (AES_BLOCK_SIZE == j)) {
            a = _mm_loadu_si128((__m128i*)input);
            b = _mm_xor_si128(a, (block + l)->i128);
            _mm_storeu_si128((__m128i*)output, b);
            input  += AES_BLOCK_SIZE;
            output += AES_BLOCK_SIZE;
        }
        else {
            for (k = i + j; i < k; i++, input++, output++)
                output[0] = input[0] ^ (block + l)->i8[i];
        }

        if (++l == BLOCK_NUM)
            l = 0; /* pre-encrypted blocks had been used up */
        offset += j;
        length -= j;
    }

    return AESNI_SUCCESS;
}

int aesni_encrypt(unsigned char *key,
                  AES_MODE       mode,
                  unsigned char *input,
                  unsigned char *output,
                  unsigned long  length)
{
    __declspec(align(16)) aes_encrypt_ctx ctx;
    int ret;
    unsigned long nblocks;
    ENCRYPT_EXPAND_KEY expand_key;
    ENCRYPT_BLOCK encrypt_block;
    
    if ((length & (AES_BLOCK_SIZE - 1)) != 0) {
        return AESNI_FAILURE;
    }
    
    nblocks = length / AES_BLOCK_SIZE;

    if (has_aesni() && !no_ni) {
        switch (mode) {
            case AESNI_128:
                expand_key = aesni_encrypt_key128_ni;
                encrypt_block = aesni_encrypt128_ni;
                break;
            case AESNI_192:
                expand_key = aesni_encrypt_key192_ni;
                encrypt_block = aesni_encrypt192_ni;
                break;
            case AESNI_256:
                expand_key = aesni_encrypt_key256_ni;
                encrypt_block = aesni_encrypt256_ni;
                break;
            default:
                return AESNI_FAILURE;
        }
    } else {
        switch (mode) {
            case AESNI_128:
                expand_key = aesni_encrypt_key128_no;
                encrypt_block = aesni_encrypt128_no;
                break;
            case AESNI_192:
                expand_key = aesni_encrypt_key192_no;
                encrypt_block = aesni_encrypt192_no;
                break;
            case AESNI_256:
                expand_key = aesni_encrypt_key256_no;
                encrypt_block = aesni_encrypt256_no;
                break;
            default:
                return AESNI_FAILURE;
        }
    }

    ret = expand_key(key, &ctx);
    if (AESNI_SUCCESS != ret)
        return ret;
    ret = encrypt_block(&ctx, input, output, nblocks);
    return ret;
}

int aesni_decrypt(unsigned char *key,
                  AES_MODE       mode,
                  unsigned char *input,
                  unsigned char *output,
                  unsigned long  length)
{   
    __declspec(align(16)) aes_decrypt_ctx ctx;
    int ret;
    unsigned long nblocks;
    DECRYPT_EXPAND_KEY expand_key;
    DECRYPT_BLOCK decrypt_block;

    
    if ((length & (AES_BLOCK_SIZE - 1)) != 0) {
        return AESNI_FAILURE;
    }
    
    nblocks = length / AES_BLOCK_SIZE;

    if (has_aesni() && !no_ni) {
        switch (mode) {
            case AESNI_128:
                expand_key = aesni_decrypt_key128_ni;
                decrypt_block = aesni_decrypt128_ni;
                break;
            case AESNI_192:
                expand_key = aesni_decrypt_key192_ni;
                decrypt_block = aesni_decrypt192_ni;
                break;
            case AESNI_256:
                expand_key = aesni_decrypt_key256_ni;
                decrypt_block = aesni_decrypt256_ni;
                break;
            default:
                return AESNI_FAILURE;
        }
    } else {
        switch (mode) {
            case AESNI_128:
                expand_key = aesni_decrypt_key128_no;
                decrypt_block = aesni_decrypt128_no;
                break;
            case AESNI_192:
                expand_key = aesni_decrypt_key192_no;
                decrypt_block = aesni_decrypt192_no;
                break;
            case AESNI_256:
                expand_key = aesni_decrypt_key256_no;
                decrypt_block = aesni_decrypt256_no;
                break;
            default:
                return AESNI_FAILURE;
        }
    }

    ret = expand_key(key, &ctx);
    if (AESNI_SUCCESS != ret)
        return ret;
    ret = decrypt_block(&ctx, input, output, nblocks);
    return ret;
}

int aesni_crypt_ctr(unsigned char     *key,
                    AES_MODE           mode,
                    unsigned char     *input,
                    unsigned char     *output,
                    unsigned long long offset,
                    unsigned long      length,
                    unsigned char      nonce[4])
{
    __declspec(align(16)) aesni_ctr_ctx ctx;
    int ret;
    ENCRYPT_EXPAND_KEY expand_key;;

    if (has_aesni() && !no_ni) {
        switch (mode) {
            case AESNI_128:
                expand_key = aesni_encrypt_key128_ni;
                ctx.encrypt = aesni_encrypt128_ni;
                break;
            case AESNI_192:
                expand_key = aesni_encrypt_key192_ni;
                ctx.encrypt = aesni_encrypt192_ni;
                break;
            case AESNI_256:
                expand_key = aesni_encrypt_key256_ni;
                ctx.encrypt = aesni_encrypt256_ni;
                break;
            default:
                return AESNI_FAILURE;
        }
    } else {
        switch (mode) {
            case AESNI_128:
                expand_key = aesni_encrypt_key128_no;
                ctx.encrypt = aesni_encrypt128_no;
                break;
            case AESNI_192:
                expand_key = aesni_encrypt_key192_no;
                ctx.encrypt = aesni_encrypt192_no;
                break;
            case AESNI_256:
                expand_key = aesni_encrypt_key256_no;
                ctx.encrypt = aesni_encrypt256_no;
                break;
            default:
                return AESNI_FAILURE;
        }
    }

    ret = expand_key(key, (aes_encrypt_ctx *)ctx.encctx);
    if (AESNI_SUCCESS != ret)
        return ret;

    return aesni_crypt_ctr_ctx(&ctx, input, output, offset, length, nonce);
}
