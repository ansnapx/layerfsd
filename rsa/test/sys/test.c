#include <ntddk.h>          // various NT definitions
#include <string.h>

#include "rsaeuro.h"
#include "rsa.h"

//
// Device driver routine declarations.
//

DRIVER_INITIALIZE DriverEntry;

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#endif // ALLOC_PRAGMA

void GetElapsedTimeInit (LARGE_INTEGER *lastPerfCounter)
{
    *lastPerfCounter = KeQueryPerformanceCounter (NULL);
}

// Returns elapsed time in microseconds since last call
LONGLONG GetElapsedTime (LARGE_INTEGER *lastPerfCounter)
{
    LARGE_INTEGER freq;
    LARGE_INTEGER counter = KeQueryPerformanceCounter (&freq);

    LONGLONG elapsed = (counter.QuadPart - lastPerfCounter->QuadPart) * 1000000LL / freq.QuadPart;

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
        DbgPrint("0x%02x ", bytes[i]);
    }

    DbgPrint("\n");
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

NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT   DriverObject,
    __in PUNICODE_STRING  RegistryPath
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    R_RSA_PUBLIC_KEY  pubkey;
    R_RSA_PRIVATE_KEY prikey;
    CHAR  text[] = "this is a rsa test";
    CHAR  cypher[DATA_SIZE];
    ULONG cypher_len;
    CHAR  plain[DATA_SIZE];
    ULONG plain_len;
    LARGE_INTEGER StartTime;
    LONGLONG      ElapsedTime;
    ULONG count = LOOP_COUNT;

    R_RANDOM_STRUCT random;
    
    ASSERT(GenRsaKey((PUCHAR)&pubkey, sizeof(R_RSA_PUBLIC_KEY), (PUCHAR)&prikey, sizeof(R_RSA_PRIVATE_KEY), KEY_BITS));
	
	cypher_len = DATA_SIZE;
	RtlZeroMemory(cypher, cypher_len);
	plain_len = DATA_SIZE;
	RtlZeroMemory(plain, plain_len);
	
	GetElapsedTimeInit(&StartTime);
    
    while (count--) {
        R_RandomCreate(&random);
        ASSERT(!RSAPublicEncrypt(cypher, &cypher_len, text, sizeof(text), &pubkey, &random));
    }
    
    ElapsedTime = GetElapsedTime(&StartTime);
    
    DbgPrint("Encrypt with Pubkey, Key Bits: %u, Data Size: %u, Loop Count: %u, Elapsed Time: %llu us\n", KEY_BITS, DATA_SIZE, LOOP_COUNT, ElapsedTime);

	count = LOOP_COUNT;
	
    GetElapsedTimeInit(&StartTime);
    
    while (count--) {
        ASSERT(!RSAPrivateDecrypt(plain, &plain_len, cypher, cypher_len, &prikey));
    }
    
    ElapsedTime = GetElapsedTime(&StartTime);
    
    DbgPrint("Decrypt with Prikey, Key Bits: %u, Data Size: %u, Loop Count: %u, Elapsed Time: %llu us\n", KEY_BITS, DATA_SIZE, LOOP_COUNT, ElapsedTime);
	
	DbgPrint("plain text: %s\n", plain);

    return status;
}
