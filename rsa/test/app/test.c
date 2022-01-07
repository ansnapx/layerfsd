#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "rsaeuro.h"
#include "rsa.h"

void GetElapsedTimeInit (double *lastPerfCounter)
{
	*lastPerfCounter = GetTickCount();
}

// Returns elapsed time in microseconds since last call
double GetElapsedTime (double *lastPerfCounter)
{
    double freq;

	double elapsed = GetTickCount() - *lastPerfCounter;

    return elapsed;
}

VOID
PrintBytes(
    PUCHAR bytes,
    ULONG  length
)
{
    ULONG i;

    for (i = 0; i < length; i++) {
        printf("0x%02x ", bytes[i]);
    }

    printf("\n");
}

BOOLEAN
GenRsaKey(
    PUCHAR pubkey,
    ULONG  pubkey_len,
    PUCHAR prikey,
    ULONG  prikey_len,
    ULONG  keybits
)
{
    R_RSA_PROTO_KEY protoKey;
    R_RANDOM_STRUCT Random;

    if ((pubkey_len < sizeof(R_RSA_PUBLIC_KEY)) || (prikey_len < sizeof(R_RSA_PRIVATE_KEY))) {
        return FALSE;
    }

    protoKey.bits = keybits;
    protoKey.useFermat4 = 1;

    R_RandomCreate(&Random);

    return !R_GeneratePEMKeys((R_RSA_PUBLIC_KEY*)pubkey, (R_RSA_PRIVATE_KEY*)prikey, &protoKey, &Random);
}

#define KEY_BITS   1024
#define DATA_SIZE  128
#define LOOP_COUNT 10000

int __cdecl main(int argc, char **argv)
{
    R_RSA_PUBLIC_KEY  pubkey;
    R_RSA_PRIVATE_KEY prikey;
    CHAR  text[] = "this is a rsa test";
    CHAR  cypher[DATA_SIZE];
    ULONG cypher_len;
    CHAR  plain[DATA_SIZE];
    ULONG plain_len;
    double StartTime;
    double ElapsedTime;
    ULONG count = LOOP_COUNT;

    R_RANDOM_STRUCT random;
    
    assert(GenRsaKey((PUCHAR)&pubkey, sizeof(R_RSA_PUBLIC_KEY), (PUCHAR)&prikey, sizeof(R_RSA_PRIVATE_KEY), KEY_BITS));
	
	cypher_len = DATA_SIZE;
	RtlZeroMemory(cypher, cypher_len);
	plain_len = DATA_SIZE;
	RtlZeroMemory(plain, plain_len);
	
	GetElapsedTimeInit(&StartTime);
    
    while (count--) {
        R_RandomCreate(&random);
        assert(!RSAPublicEncrypt(cypher, &cypher_len, text, sizeof(text), &pubkey, &random));
    }
    
    ElapsedTime = GetElapsedTime(&StartTime);
    
	printf("Encrypt with Pubkey, Key Bits: %u, Data Size: %u, Loop Count: %u, Elapsed Time: %f ms\n", KEY_BITS, DATA_SIZE, LOOP_COUNT, ElapsedTime);

	count = LOOP_COUNT;
	
    GetElapsedTimeInit(&StartTime);
    
    while (count--) {
		assert(!RSAPrivateDecrypt(plain, &plain_len, cypher, cypher_len, &prikey));
    }
    
    ElapsedTime = GetElapsedTime(&StartTime);
    
	printf("Decrypt with Prikey, Key Bits: %u, Data Size: %u, Loop Count: %u, Elapsed Time: %f ms\n", KEY_BITS, DATA_SIZE, LOOP_COUNT, ElapsedTime);
	
	printf("plain text: %s\n", plain);

    return 0;
}
