/*

	R_DH.C - Diffie-Hellman routines for RSAEURO

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to you applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	Diffie-Hellman Key Agreement functions.

	Revision History.
		0.90, First revision, this simply does the required
		Diffie-Hellman key agreement stuff, based heavily on
		RSAREF(tm) and relies heavily on the NN.C routines.

*/

#include "rsaeuro.h"
#include "r_random.h"
#include "nn.h"
#include "prime.h"

		/* Key agreement prep */
#define PREP(x, y, z, a) { \
	NN_Assign (x, y, a);\
	NN_ASSIGN_DIGIT (z, 1, a);\
	NN_Sub (z, t, z, a);\
	NN_Add (x, x, z, a);\
}

/* Generates Diffie-Hellman key agreement parameters. */

int R_GenerateDHParams(params, primeBits, subPrimeBits, randomStruct)
R_DH_PARAMS *params;                       /* new Diffie-Hellman parameters */
unsigned int primeBits;                    /* length of prime in bits */
unsigned int subPrimeBits;                 /* length of subprime in bits */
R_RANDOM_STRUCT *randomStruct;             /* random structure */
{
	int status;
	NN_DIGIT g[MAX_NN_DIGITS], p[MAX_NN_DIGITS], q[MAX_NN_DIGITS],
		t[MAX_NN_DIGITS], u[MAX_NN_DIGITS], v[MAX_NN_DIGITS];
	unsigned int pDigits;

	pDigits = (primeBits + NN_DIGIT_BITS - 1) / NN_DIGIT_BITS;

	/* Generate a subprime q between 2^(subPrimeBits-1) and
		 2^subPrimeBits-1, searching in steps of 2.	 */

	NN_Assign2Exp(t, subPrimeBits-1, pDigits);
	PREP(u, t, v, pDigits);
	NN_ASSIGN_DIGIT(v, 2, pDigits);
	if((status = GeneratePrime (q, t, u, v, pDigits, randomStruct)) != 0)
		return(status);

	/* Generate a prime p between 2^(primeBits-1) and 2^primeBits-1,
		 searching in steps of 2*q. */
	NN_Assign2Exp(t, primeBits-1, pDigits);
	PREP(u, t, v, pDigits);
	NN_LShift(v, q, 1, pDigits);
	if((status = GeneratePrime (p, t, u, v, pDigits, randomStruct)) != 0)
		return(status);

	/* Generate the generator g for subgroup as 2^((p-1)/q) mod p. */

	NN_ASSIGN_DIGIT(g, 2, pDigits);
	NN_Div(t, u, p, pDigits, q, pDigits);
	NN_ModExp(g, g, t, pDigits, p, pDigits);

	params->generatorLen = params->primeLen = DH_PRIME_LEN(primeBits);
	NN_Encode(params->prime, params->primeLen, p, pDigits);
	NN_Encode(params->generator, params->generatorLen, g, pDigits);

	return(ID_OK);
}

/* Setup Diffie-Hellman key agreement. Public value has same length
	 as prime. */

int R_SetupDHAgreement(publicValue, privateValue, privateValueLen,
		params, randomStruct)
unsigned char *publicValue;                             /* new public value */
unsigned char *privateValue;                           /* new private value */
unsigned int privateValueLen;                    /* length of private value */
R_DH_PARAMS *params;                           /* Diffie-Hellman parameters */
R_RANDOM_STRUCT *randomStruct;                          /* random structure */
{
	int status;
	NN_DIGIT g[MAX_NN_DIGITS], p[MAX_NN_DIGITS], x[MAX_NN_DIGITS],
		y[MAX_NN_DIGITS];
	unsigned int pDigits, xDigits;

	NN_Decode(p, MAX_NN_DIGITS, params->prime, params->primeLen);
	pDigits = NN_Digits(p, MAX_NN_DIGITS);
	NN_Decode(g, pDigits, params->generator, params->generatorLen);


	/* Generate the private value of key agreement. */

	if((status = R_GenerateBytes(privateValue, privateValueLen, randomStruct)) != 0)
		return (status);

	NN_Decode(x, pDigits, privateValue, privateValueLen);
	xDigits = NN_Digits(x, pDigits);

	/* Compute y = g^x mod p. */

	NN_ModExp(y, g, x, xDigits, p, pDigits);

	NN_Encode(publicValue, params->primeLen, y, pDigits);

	/* Clear sensitive information. */

	R_memset((POINTER)x, 0, sizeof(x));

	return(ID_OK);
}

/* Computes agreed key from the other party's public value, a private
	 value, and Diffie-Hellman parameters. Other public value and
	 agreed-upon key have same length as prime.

	 Requires otherPublicValue < prime. */

int R_ComputeDHAgreedKey(agreedKey, otherPublicValue, privateValue,
		privateValueLen, params)
unsigned char *agreedKey;                                 /* new agreed key */
unsigned char *otherPublicValue;                    /* other's public value */
unsigned char *privateValue;                               /* private value */
unsigned int privateValueLen;                    /* length of private value */
R_DH_PARAMS *params;                           /* Diffie-Hellman parameters */
{
	NN_DIGIT p[MAX_NN_DIGITS], x[MAX_NN_DIGITS], y[MAX_NN_DIGITS],
		z[MAX_NN_DIGITS];
	unsigned int pDigits, xDigits;

	NN_Decode(p, MAX_NN_DIGITS, params->prime, params->primeLen);
	pDigits = NN_Digits(p, MAX_NN_DIGITS);
	NN_Decode(x, pDigits, privateValue, privateValueLen);
	NN_Decode(y, pDigits, otherPublicValue, params->primeLen);
	xDigits = NN_Digits (x, pDigits);

	if(NN_Cmp(y, p, pDigits) >= 0)
		return(RE_DATA);

	/* Compute z = y^x mod p. */

	NN_ModExp(z, y, x, xDigits, p, pDigits);

	NN_Encode(agreedKey, params->primeLen, z, pDigits);

	/* Clear sensitive information. */

	R_memset((POINTER)x, 0, sizeof(x));
	R_memset((POINTER)z, 0, sizeof(z));

	return(ID_OK);
}
