/*
	RSA.C - RSA routines for RSAEURO

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	RSA encryption performed as defined in the PKCS (#1) by RSADSI.

	Revision history
		0.90 First revision, code produced very similar to that
		of RSAREF(tm), still it worked fine.

        0.91 Second revision, code altered to aid speeding up.
		Used pointer accesses to arrays to speed up some parts,
		mainly during the loops.

        1.03 Third revision, Random Structure initialization
        double check, RSAPublicEncrypt can now return RE_NEED_RANDOM.
*/

#include "rsaeuro.h"
#include "r_random.h"
#include "rsa.h"
#include "nn.h"

#ifdef RSA_WINDOWS_DRIVER

#include <ntddk.h>

/* rsa stack usage optimization */

#if RSA_STACK_PER_CPU

typedef struct _lfs_rsa_stack {
    union {
        struct {
            unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];

            NN_DIGIT c[MAX_NN_DIGITS], e[MAX_NN_DIGITS], m[MAX_NN_DIGITS],
                     n[MAX_NN_DIGITS];
        } pub;

        struct {
            unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];

            NN_DIGIT c [MAX_NN_DIGITS], cP[MAX_NN_DIGITS], cQ[MAX_NN_DIGITS],
                     dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS], mP[MAX_NN_DIGITS],
                     mQ[MAX_NN_DIGITS], n [MAX_NN_DIGITS], p [MAX_NN_DIGITS],
                     q [MAX_NN_DIGITS], t [MAX_NN_DIGITS], qInv[MAX_NN_DIGITS];
        } pri;
    };

    KSPIN_LOCK  lock;

    KIRQL       irql;
    UCHAR       id;

} lfs_rsa_stack_t;

lfs_rsa_stack_t *g_rsa_stack = NULL;

int lfs_init_rsa_stack()
{
    ULONG i, max = KeQueryMaximumProcessorCount();
    g_rsa_stack = ExAllocatePoolWithTag(NonPagedPool, max * 
                                        sizeof(lfs_rsa_stack_t),
                                        'ASRL');
    if (NULL == g_rsa_stack) {
        return FALSE;
    }

    memset(g_rsa_stack, 0, max * sizeof(lfs_rsa_stack_t));
    for (i = 0; i < max; i++) {
        KeInitializeSpinLock(&g_rsa_stack[i].lock);
        g_rsa_stack[i].id = (UCHAR)i;
    }

    return TRUE;
}

void lfs_fini_rsa_stack()
{
    if (g_rsa_stack)
        ExFreePool(g_rsa_stack);
}

lfs_rsa_stack_t *lfs_grab_rsa_stack()
{
    lfs_rsa_stack_t *s = NULL;

    do {
        if (s)
            KeReleaseSpinLock(&s->lock, s->irql);
        s = &g_rsa_stack[KeGetCurrentProcessorNumber()];
        KeAcquireSpinLock(&s->lock, &s->irql);
    } while (KeGetCurrentProcessorNumber() != s->id);

    return s;
}

void lfs_drop_rsa_stack(lfs_rsa_stack_t *s)
{
    ASSERT(DISPATCH_LEVEL == KeGetCurrentIrql());
    KeReleaseSpinLock(&s->lock, s->irql);
}

# else /* RSA_STACK_PER_CPU */

typedef struct _lfs_rsa_stack {
    union {
        struct {
            unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];

            NN_DIGIT c[MAX_NN_DIGITS], e[MAX_NN_DIGITS], m[MAX_NN_DIGITS],
                     n[MAX_NN_DIGITS];
        } pub;

        struct {
            unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];

            NN_DIGIT c [MAX_NN_DIGITS], cP[MAX_NN_DIGITS], cQ[MAX_NN_DIGITS],
                     dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS], mP[MAX_NN_DIGITS],
                     mQ[MAX_NN_DIGITS], n [MAX_NN_DIGITS], p [MAX_NN_DIGITS],
                     q [MAX_NN_DIGITS], t [MAX_NN_DIGITS], qInv[MAX_NN_DIGITS];
        } pri;
    };
} lfs_rsa_stack_t;

lfs_rsa_stack_t *lfs_grab_rsa_stack()
{
    lfs_rsa_stack_t *s = ExAllocatePoolWithTag(NonPagedPool, sizeof(*s), 'ASRL');
    return s;
}

void lfs_drop_rsa_stack(lfs_rsa_stack_t *s)
{
    if (s)
        ExFreePool(s);
}

int lfs_init_rsa_stack()
{
    return TRUE;
}

void lfs_fini_rsa_stack()
{
}

# endif /* RSA_STACK_PER_CPU */

#else   /* Kernel or User mode */

#include <malloc.h>

typedef struct _lfs_rsa_stack {
    union {
        struct {
            unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];

            NN_DIGIT c[MAX_NN_DIGITS], e[MAX_NN_DIGITS], m[MAX_NN_DIGITS],
                     n[MAX_NN_DIGITS];
        } pub;

        struct {
            unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];

            NN_DIGIT c [MAX_NN_DIGITS], cP[MAX_NN_DIGITS], cQ[MAX_NN_DIGITS],
                     dP[MAX_NN_DIGITS], dQ[MAX_NN_DIGITS], mP[MAX_NN_DIGITS],
                     mQ[MAX_NN_DIGITS], n [MAX_NN_DIGITS], p [MAX_NN_DIGITS],
                     q [MAX_NN_DIGITS], t [MAX_NN_DIGITS], qInv[MAX_NN_DIGITS];
        } pri;
    };
} lfs_rsa_stack_t;

lfs_rsa_stack_t *lfs_grab_rsa_stack()
{
    lfs_rsa_stack_t *s = malloc(sizeof(*s));
    return s;
}

void lfs_drop_rsa_stack(lfs_rsa_stack_t *s)
{
    if (s)
        free(s);
}

#endif /* RSA_WINDOWS_DRIVER */

static int rsapublicfunc PROTO_LIST((lfs_rsa_stack_t *s, unsigned char *, unsigned int *, unsigned char *, unsigned int, R_RSA_PUBLIC_KEY *));
static int rsaprivatefunc PROTO_LIST((lfs_rsa_stack_t *s, unsigned char *, unsigned int *, unsigned char *, unsigned int, R_RSA_PRIVATE_KEY *));

/* RSA encryption, according to RSADSI's PKCS #1. */

int __stdcall RSAPublicEncrypt(output, outputLen, input, inputLen, publicKey, randomStruct)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PUBLIC_KEY *publicKey;    /* RSA public key */
R_RANDOM_STRUCT *randomStruct;  /* random structure */
{
    lfs_rsa_stack_t *s = NULL;
	int status;
	unsigned char byte, *pkcsBlock;
	unsigned int i, modulusLen;

    __try {

	    modulusLen = (publicKey->bits + 7) / 8;
        if (modulusLen > MAX_RSA_MODULUS_LEN) {
            status = RE_LEN;
            __leave;
        }

	    if (inputLen + 11 > modulusLen) {
            status = RE_LEN;
            __leave;
        }

        R_GetRandomBytesNeeded(&i, randomStruct);
        if (i != 0) {
            status = RE_NEED_RANDOM;
            __leave;
        }

        s = lfs_grab_rsa_stack();
        if (NULL == s) {
            status = RE_PUBLIC_KEY;
            __leave;
        }
        pkcsBlock = &s->pub.pkcsBlock[0];
	    *pkcsBlock = 0;                 /* PKCS Block Makeup */

		/* block type 2 */
	    *(pkcsBlock+1) = 2;

	    for(i = 2; i < modulusLen - inputLen - 1; i++) {
		    /* Find nonzero random byte. */
		    do {
                /* random bytes used to pad the PKCS Block */
			    R_GenerateBytes(&byte, 1, randomStruct);
		    }while(byte == 0);
		    *(pkcsBlock+i) = byte;
	    }

	    /* separator */
	    pkcsBlock[i++] = 0;

	    R_memcpy((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);

	    status = rsapublicfunc(s, output, outputLen, pkcsBlock, modulusLen, publicKey);

	    /* Clear sensitive information. */

	    byte = 0;
	    R_memset((POINTER)pkcsBlock, 0, MAX_RSA_MODULUS_LEN);

    } __finally {
        if (s)
            lfs_drop_rsa_stack(s);
    }

	return(status);
}

/* RSA decryption, according to RSADSI's PKCS #1. */

int __stdcall RSAPublicDecrypt(output, outputLen, input, inputLen, publicKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PUBLIC_KEY *publicKey;    /* RSA public key */
{
    lfs_rsa_stack_t *s = NULL;
	int status;
	unsigned char *pkcsBlock;
	unsigned int i, modulusLen, pkcsBlockLen;

    __try {

	    modulusLen = (publicKey->bits + 7) / 8;
        if (modulusLen > MAX_RSA_MODULUS_LEN) {
            status = RE_LEN;
            __leave;
        }
	    if (inputLen > modulusLen) {
            status = RE_LEN;
            __leave;
        }

        s = lfs_grab_rsa_stack();
        if (NULL == s) {
            status = RE_PUBLIC_KEY;
            __leave;
        }
        pkcsBlock = &s->pub.pkcsBlock[0];

	    status = rsapublicfunc(s, pkcsBlock, &pkcsBlockLen, input, inputLen, publicKey);
	    if(status)
		    __leave;

	    if (pkcsBlockLen != modulusLen) {
            status = RE_LEN;
            __leave;
        }

	    /* Require block type 1. */
	    if ((pkcsBlock[0] != 0) || (pkcsBlock[1] != 1)) {
            status = RE_DATA;
            __leave;
        }
    
	    for (i = 2; i < modulusLen-1; i++)
		    if (*(pkcsBlock+i) != 0xff)
			    break;

	    /* separator check */
	    if (pkcsBlock[i++] != 0) {
            status = RE_DATA;
            __leave;
        }

	    *outputLen = modulusLen - i;
	    if(*outputLen + 11 > modulusLen) {
            status = RE_DATA;
            __leave;
        }

	    R_memcpy((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

	    /* Clear sensitive information. */
	    R_memset((POINTER)pkcsBlock, 0, MAX_RSA_MODULUS_LEN);

    } __finally {
        if (s)
            lfs_drop_rsa_stack(s);
    }

	return(status);
}

/* RSA encryption, according to RSADSI's PKCS #1. */

int __stdcall RSAPrivateEncrypt(output, outputLen, input, inputLen, privateKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PRIVATE_KEY *privateKey;  /* RSA private key */
{
    lfs_rsa_stack_t *s = NULL;
	int status;
	unsigned char *pkcsBlock;
	unsigned int i, modulusLen;

    __try {

	    modulusLen = (privateKey->bits + 7) / 8;
        if (modulusLen > MAX_RSA_MODULUS_LEN) {
            status = RE_LEN;
            __leave;
        }

	    if (inputLen + 11 > modulusLen) {
            status = RE_LEN;
            __leave;
        }

        s = lfs_grab_rsa_stack();
        if (NULL == s) {
            status = RE_PRIVATE_KEY;
            __leave;
        }
        pkcsBlock = &s->pri.pkcsBlock[0];

	    *pkcsBlock = 0;
	    /* block type 1 */
	    *(pkcsBlock+1) = 1;

	    for (i = 2; i < modulusLen - inputLen - 1; i++)
		    *(pkcsBlock+i) = 0xff;

	    /* separator */
	    pkcsBlock[i++] = 0;

	    R_memcpy((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);

	    status = rsaprivatefunc(s, output, outputLen, pkcsBlock, modulusLen, privateKey);

	    /* Clear sensitive information. */
	    R_memset((POINTER)pkcsBlock, 0, MAX_RSA_MODULUS_LEN);

    } __finally {
        if (s)
            lfs_drop_rsa_stack(s);
    }

	return(status);
}

/* RSA decryption, according to RSADSI's PKCS #1. */

int __stdcall RSAPrivateDecrypt(output, outputLen, input, inputLen, privateKey)
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PRIVATE_KEY *privateKey;  /* RSA private key */
{
    lfs_rsa_stack_t *s = NULL;
	int status;
	unsigned char *pkcsBlock;
	unsigned int i, modulusLen, pkcsBlockLen;

    __try {

	    modulusLen = (privateKey->bits + 7) / 8;
        if (modulusLen > MAX_RSA_MODULUS_LEN) {
            status = RE_LEN;
            __leave;
        }

	    if(inputLen > modulusLen) {
            status = RE_LEN;
            __leave;
        }

        s = lfs_grab_rsa_stack();
        if (NULL == s) {
            status = RE_PRIVATE_KEY;
            __leave;
        }
        pkcsBlock = &s->pri.pkcsBlock[0];

	    status = rsaprivatefunc(s, pkcsBlock, &pkcsBlockLen, input, inputLen, privateKey);
	    if (status)
		    __leave;

	    if (pkcsBlockLen != modulusLen) {
            status = RE_LEN;
            __leave;
        }

	    /* We require block type 2. */
	    if ((*pkcsBlock != 0) || (*(pkcsBlock+1) != 2)) {
            status = RE_DATA;
            __leave;
        }

	    for (i = 2; i < modulusLen-1; i++)
		    /* separator */
		    if (*(pkcsBlock+i) == 0)
			    break;

	    i++;
	    if(i >= modulusLen) {
            status = RE_DATA;
            __leave;
        }

	    *outputLen = modulusLen - i;
	    if(*outputLen + 11 > modulusLen) {
            status = RE_DATA;
            __leave;
        }

	    R_memcpy((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

	    /* Clear sensitive information. */
	    R_memset((POINTER)pkcsBlock, 0, MAX_RSA_MODULUS_LEN);

    } __finally {
        if (s)
            lfs_drop_rsa_stack(s);
    }

	return(status);
}

/* Raw RSA public-key operation. Output has same length as modulus.

	 Requires input < modulus.
*/
static int rsapublicfunc(s, output, outputLen, input, inputLen, publicKey)
lfs_rsa_stack_t *s;
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PUBLIC_KEY *publicKey;    /* RSA public key */
{
	NN_DIGIT *c = s->pub.c, *e = s->pub.e, *m = s->pub.m,
		     *n = s->pub.n;
	unsigned int eDigits, nDigits;

		/* decode the required RSA function input data */
	NN_Decode(m, MAX_NN_DIGITS, input, inputLen);
	NN_Decode(n, MAX_NN_DIGITS, publicKey->modulus, MAX_RSA_MODULUS_LEN);
	NN_Decode(e, MAX_NN_DIGITS, publicKey->exponent, MAX_RSA_MODULUS_LEN);

	nDigits = NN_Digits(n, MAX_NN_DIGITS);
	eDigits = NN_Digits(e, MAX_NN_DIGITS);

	if(NN_Cmp(m, n, nDigits) >= 0)
		return(RE_DATA);

	*outputLen = (publicKey->bits + 7) / 8;

	/* Compute c = m^e mod n.  To perform actual RSA calc.*/

	NN_ModExp (c, m, e, eDigits, n, nDigits);

	/* encode output to standard form */
	NN_Encode (output, *outputLen, c, nDigits);

	/* Clear sensitive information. */

	R_memset((POINTER)c, 0, sizeof(s->pub.c));
	R_memset((POINTER)m, 0, sizeof(s->pub.m));

	return(ID_OK);
}

/* Raw RSA private-key operation. Output has same length as modulus.

	 Requires input < modulus.
*/

static int rsaprivatefunc(s, output, outputLen, input, inputLen, privateKey)
lfs_rsa_stack_t *s;
unsigned char *output;          /* output block */
unsigned int *outputLen;        /* length of output block */
unsigned char *input;           /* input block */
unsigned int inputLen;          /* length of input block */
R_RSA_PRIVATE_KEY *privateKey;  /* RSA private key */
{
	NN_DIGIT *c = s->pri.c, *cP = s->pri.cP, *cQ = s->pri.cQ,
		*dP = s->pri.dP, *dQ = s->pri.dQ, *mP = s->pri.mP,
		*mQ = s->pri.mQ, *n  = s->pri.n, *p = s->pri.p,
        *q = s->pri.q, *qInv = s->pri.qInv, *t = s->pri.t;
	unsigned int cDigits, nDigits, pDigits;

	/* decode required input data from standard form */
	NN_Decode(c, MAX_NN_DIGITS, input, inputLen);           /* input */

					/* private key data */
	NN_Decode(p, MAX_NN_DIGITS, privateKey->prime[0], MAX_RSA_PRIME_LEN);
	NN_Decode(q, MAX_NN_DIGITS, privateKey->prime[1], MAX_RSA_PRIME_LEN);
	NN_Decode(dP, MAX_NN_DIGITS, privateKey->primeExponent[0], MAX_RSA_PRIME_LEN);
	NN_Decode(dQ, MAX_NN_DIGITS, privateKey->primeExponent[1], MAX_RSA_PRIME_LEN);
	NN_Decode(n, MAX_NN_DIGITS, privateKey->modulus, MAX_RSA_MODULUS_LEN);
	NN_Decode(qInv, MAX_NN_DIGITS, privateKey->coefficient, MAX_RSA_PRIME_LEN);
		/* work out lengths of input components */

    cDigits = NN_Digits(c, MAX_NN_DIGITS);
    pDigits = NN_Digits(p, MAX_NN_DIGITS);
	nDigits = NN_Digits(n, MAX_NN_DIGITS);


	if(NN_Cmp(c, n, nDigits) >= 0)
		return(RE_DATA);

	*outputLen = (privateKey->bits + 7) / 8;

	/* Compute mP = cP^dP mod p  and  mQ = cQ^dQ mod q. (Assumes q has
		 length at most pDigits, i.e., p > q.)
	*/

	NN_Mod(cP, c, cDigits, p, pDigits);
	NN_Mod(cQ, c, cDigits, q, pDigits);

	NN_AssignZero(mP, nDigits);
	NN_ModExp(mP, cP, dP, pDigits, p, pDigits);

	NN_AssignZero(mQ, nDigits);
	NN_ModExp(mQ, cQ, dQ, pDigits, q, pDigits);

	/* Chinese Remainder Theorem:
			m = ((((mP - mQ) mod p) * qInv) mod p) * q + mQ.
	*/

	if(NN_Cmp(mP, mQ, pDigits) >= 0) {
		NN_Sub(t, mP, mQ, pDigits);
	}else{
		NN_Sub(t, mQ, mP, pDigits);
		NN_Sub(t, p, t, pDigits);
	}

	NN_ModMult(t, t, qInv, p, pDigits);
	NN_Mult(t, t, q, pDigits);
	NN_Add(t, t, mQ, nDigits);

	/* encode output to standard form */
	NN_Encode (output, *outputLen, t, nDigits);

	/* Clear sensitive information. */
	R_memset((POINTER)c, 0, sizeof(s->pri.c));
	R_memset((POINTER)cP, 0, sizeof(s->pri.cP));
	R_memset((POINTER)cQ, 0, sizeof(s->pri.cQ));
	R_memset((POINTER)dP, 0, sizeof(s->pri.dP));
	R_memset((POINTER)dQ, 0, sizeof(s->pri.dQ));
	R_memset((POINTER)mP, 0, sizeof(s->pri.mP));
	R_memset((POINTER)mQ, 0, sizeof(s->pri.mQ));
	R_memset((POINTER)p, 0, sizeof(s->pri.p));
	R_memset((POINTER)q, 0, sizeof(s->pri.q));
	R_memset((POINTER)qInv, 0, sizeof(s->pri.qInv));
	R_memset((POINTER)t, 0, sizeof(s->pri.t));
	return(ID_OK);
}
