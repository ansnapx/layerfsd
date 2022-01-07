#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <windows.h>
#include <assert.h>
#include <time.h>
#include "aesni.h"

#pragma intrinsic( __rdtsc )

__inline volatile unsigned long long read_tsc(void)
{
    return __rdtsc();
}

#define BLOCK_LEN 16
#define BUF_LEN (2100)

static unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static unsigned char notice[4] = {0x11, 0x22, 0x33, 0x44};

static aesni_ctr_ctx ctx;

int __cdecl main(int argc, char *argv[])
{
    FILE *fin = NULL, *fout = NULL;
    AES_MODE mode;
    unsigned char *inbuf = NULL, *outbuf = NULL;
    unsigned long long offset = 0;
    unsigned long rlen, wlen;
    int ret;
    int i;
    long size;

    if (argc < 4) {
        printf("usage %s <input file> <output file> <128 | 192 | 256>\n", argv[0]);
        goto l_end;
    }

    inbuf  = (unsigned char *)malloc(BUF_LEN);
    outbuf = (unsigned char *)malloc(BUF_LEN);

    if (!inbuf || !outbuf)
        goto l_end;

    aesni_init();

    if(!(fin = fopen(argv[1], "rb")))   // try to open the input file
    {
        printf("The input file: %s could not be opened\n", argv[1]);
        goto l_end;
    }

    if(!(fout = fopen(argv[2], "wb")))  // try to open the output file
    {
        printf("The output file: %s could not be opened\n", argv[2]);
        goto l_end;
    }

    if (0 == strcmp(argv[3], "128"))
        mode = AESNI_128;
    else if (0 == strcmp(argv[3], "192"))
        mode = AESNI_192;
    else if (0 == strcmp(argv[3], "256"))
        mode = AESNI_256;
    else
        goto l_end;

    /* fill random for key and notice */
    srand((unsigned int)time(NULL));
    for (i = 0; i < sizeof(key); i++)
        key[i] = rand() & 0xF + key[i];

    for (i = 0; i < sizeof(notice); i++)
        notice[i] = rand() & 0xF + notice[i];

    /* init ctx */
    ret = aesni_init_ctr_ctx(key, mode, &ctx);
    assert(AESNI_SUCCESS == ret);

    /* encrypt file */
    offset = 0;
    while (rlen = (unsigned long)fread(inbuf, 1, BUF_LEN, fin)) {
        ret = aesni_encrypt_ctr(key, mode, inbuf, outbuf, offset, rlen, notice);
        assert(AESNI_SUCCESS == ret);

        wlen = fwrite(outbuf, 1, rlen, fout);
        assert(wlen == rlen);

        offset += rlen;
    }

    if(fout)
        fclose(fout);

    if(fin)
        fclose(fin);

    fout = fin = NULL;

    /* verify encrypted file */
    if(!(fin = fopen(argv[1], "rb")))   // try to open the input file
    {
        printf("The input file: %s could not be opened\n", argv[1]);
        goto l_end;
    }

    if(!(fout = fopen(argv[2], "rb")))  // try to open the output file
    {
        printf("The output file: %s could not be opened\n", argv[2]);
        goto l_end;
    }

    fseek(fout, 0, SEEK_END);
    size = ftell(fout);

    srand((unsigned int)time(NULL));

    for (i = 0; i < 100000; i++) {
        offset = rand() % size;
        srand((unsigned int)offset);
        rlen = rand() % size;
        srand((unsigned int)rlen);

        rlen = rlen > BUF_LEN ? BUF_LEN : rlen;

        fseek(fout, (long)offset, SEEK_SET);
        rlen = (unsigned long)fread(inbuf, 1, rlen, fout);
        ret = aesni_decrypt_ctr_ctx(&ctx, inbuf, outbuf, offset, rlen, notice);
        assert(AESNI_SUCCESS == ret);
        fseek(fin, (long)offset, SEEK_SET);
        rlen = (unsigned long)fread(inbuf, 1, rlen, fin);
        if (0 == memcmp(inbuf, outbuf, rlen))
            printf("verify offset: [0x%llx], len: [%u] [OK]\n", offset, rlen);
        else {
            printf("verify offset: [0x%llx], len: [%u] [FAIL]\n", offset, rlen);
            goto l_end;
        }
    }

l_end:
    if(fout)
        fclose(fout);

    if(fin)
        fclose(fin);

    if (outbuf)
        free(outbuf);

    if (inbuf)
        free(inbuf);
    
    aesni_fini();

    return 0;
}
