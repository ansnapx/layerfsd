#include <fltKernel.h>
#include "aesni.h"

typedef struct _AESTEST_STREAM_HANDLE_CONTEXT {

    POBJECT_NAME_INFORMATION NameInfo;
    aesni_ctx                ctx_ni;
    aesni_ctx                ctx_no;
    aesni_ctr_ctx            ctr_ctx_ni;
    aesni_ctr_ctx            ctr_ctx_no;
    ULONGLONG                DataSize;
    LONGLONG                 AESNI_Time;
    LONGLONG                 AESNI_CTR_Time;
    LONGLONG                 AES_Time;
    LONGLONG                 AES_CTR_Time;
    LONGLONG                 AESNI_CTX_Time;
    LONGLONG                 AESNI_CTR_CTX_Time;
    LONGLONG                 AES_CTX_Time;
    LONGLONG                 AES_CTR_CTX_Time;
    
} AESTEST_STREAM_HANDLE_CONTEXT, *PAESTEST_STREAM_HANDLE_CONTEXT;

#define FLAG_AESNI      0x0001
#define FLAG_AESNI_CTR  0x0002
#define FLAG_AES        0x0004
#define FLAG_AES_CTR    0x0008

typedef struct _AESTEST_DATA {

    PDRIVER_OBJECT DriverObject;

    PFLT_FILTER    Filter;

    ULONG          AesFlag;
    
} AESTEST_DATA, *PAESTEST_DATA;

AESTEST_DATA AesTestData;

#define KEY_SIZE 128

UCHAR Key[KEY_SIZE];

VOID
ContextCleanup (
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    );

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

NTSTATUS
AesTestUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
AesTestQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
AesTestPreCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
AesTestPostCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
AesTestPreClose (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
AesTestPreWrite (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
AesTestPreRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
AesTestPostRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS
AesTestInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

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
    *lastPerfCounter = counter;

    return elapsed;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      AesTestPreCreate,
      AesTestPostCreate},

    { IRP_MJ_CLOSE,
      0,
      AesTestPreClose,
      NULL},

    { IRP_MJ_WRITE,
      0,
      AesTestPreWrite,
      NULL},

    { IRP_MJ_READ,
      0,
      AesTestPreRead,
      AesTestPostRead},

    { IRP_MJ_OPERATION_END}
};


const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      ContextCleanup,
      sizeof(AESTEST_STREAM_HANDLE_CONTEXT),
      'chTA' },

    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, //  Flags
    ContextRegistration,                //  Context Registration.
    Callbacks,                          //  Operation callbacks
    AesTestUnload,                      //  FilterUnload
    AesTestInstanceSetup,               //  InstanceSetup
    AesTestQueryTeardown,               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

VOID
InitializeParameters (
    __in PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This routine tries to read the filter DebugLevel parameter from
    the registry.  This value will be found in the registry location
    indicated by the RegistryPath passed in.

Arguments:

    RegistryPath - The path key passed to the driver during DriverEntry.

Return Value:

    None.

--*/
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE driverRegKey;
    NTSTATUS Status;
    ULONG resultLength;
    UNICODE_STRING valueName;
    UCHAR buffer[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( LONG )];

    AesTestData.AesFlag = FLAG_AESNI | FLAG_AESNI_CTR | FLAG_AES | FLAG_AES_CTR;

    //
    //  Open the desired registry key
    //

    InitializeObjectAttributes( &attributes,
                                RegistryPath,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                NULL );

    Status = ZwOpenKey( &driverRegKey,
                        KEY_READ,
                        &attributes );

    if (NT_SUCCESS( Status )) {

        //
        //  Read the DebugLevel value from the registry.
        //

        RtlInitUnicodeString( &valueName, L"AesFlag" );

        Status = ZwQueryValueKey( driverRegKey,
                                  &valueName,
                                  KeyValuePartialInformation,
                                  buffer,
                                  sizeof(buffer),
                                  &resultLength );

        if (NT_SUCCESS( Status )) {

            AesTestData.AesFlag = *((PULONG) &(((PKEY_VALUE_PARTIAL_INFORMATION) buffer)->Data));
        }
    }

    //
    //  Close the registry entry
    //

    ZwClose( driverRegKey );
}


NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
    )

{
    NTSTATUS status;
    ULONG    i;
    PULONG   k = (PULONG)Key;
    ULONG    seed;


    InitializeParameters( RegistryPath );

    aesni_init();

    for (i = 0; i < KEY_SIZE / sizeof(ULONG); i++) {
        seed = KeQueryTimeIncrement();
        seed = RtlRandomEx(&seed);
        if (i > 0)
            seed += k[i-1];
        k[i] = RtlRandomEx(&seed);
    }

    AesTestData.DriverObject = DriverObject;

    //
    //  Register with filter manager.
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &AesTestData.Filter );


    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Start filtering I/O
    //

    status = FltStartFiltering( AesTestData.Filter );

    return status;

}

NTSTATUS
AesTestUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for the Filter driver.  This unregisters the
    Filter with the filter manager and frees any allocated global data
    structures.

Arguments:

    None.

Return Value:

    Returns the final status of the deallocation routines.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    //
    //  Unregister the filter
    //

    FltUnregisterFilter( AesTestData.Filter );

    aesni_fini();

    return STATUS_SUCCESS;
}

NTSTATUS
AesTestInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called by the filter manager when a new instance is created.
    We specified in the registry that we only want for manual attachments,
    so that is all we should receive here.

Arguments:

    FltObjects - Describes the instance and volume which we are being asked to
        setup.

    Flags - Flags describing the type of attachment this is.

    VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
        will attach.

    VolumeFileSystemType - The file system formatted on this volume.

Return Value:

  FLT_NOTIFY_STATUS_ATTACH              - we wish to attach to the volume
  FLT_NOTIFY_STATUS_DO_NOT_ATTACH       - no, thank you

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    ASSERT( FltObjects->Filter == AesTestData.Filter );

    //
    //  Don't attach to network volumes.
    //

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

       return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
AesTestQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is the instance detach routine for the filter. This
    routine is called by filter manager when a user initiates a manual instance
    detach. This is a 'query' routine: if the filter does not want to support
    manual detach, it can return a failure status

Arguments:

    FltObjects - Describes the instance and volume for which we are receiving
        this query teardown request.

    Flags - Unused

Return Value:

    STATUS_SUCCESS - we allow instance detach to happen

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    return STATUS_SUCCESS;
}

VOID
ContextCleanup (
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    )
/*++

Routine Description:

    FltMgr calls this routine immediately before it deletes the context.

Arguments:

    Context - Pointer to the minifilter driver's portion of the context.

    ContextType - Type of context. Must be one of the following values:
        FLT_FILE_CONTEXT (Microsoft Windows Vista and later only.),
        FLT_INSTANCE_CONTEXT, FLT_STREAM_CONTEXT, FLT_STREAMHANDLE_CONTEXT,
        FLT_TRANSACTION_CONTEXT (Windows Vista and later only.), and
        FLT_VOLUME_CONTEXT

Return Value:

    None.

--*/
{
    PAGED_CODE();

    switch(ContextType) {

    case FLT_STREAMHANDLE_CONTEXT:
    {
        PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext = (PAESTEST_STREAM_HANDLE_CONTEXT) Context;

        //
        //  Free the file name
        //

        if (StreamHandleContext->NameInfo!= NULL) {

            ExFreePool(StreamHandleContext->NameInfo);
        }
    }
    
        break;

    }
}

NTSTATUS
CreateStreamHandleContext (
    PAESTEST_STREAM_HANDLE_CONTEXT *pStreamHandleContext
    )
/*++

Routine Description:

    This routine creates a new stream context

Arguments:

    StreamContext         - Returns the stream context

Return Value:

    Status

--*/
{
    NTSTATUS Status;
    PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext;

    PAGED_CODE();

    //
    //  Allocate a stream context
    //

    Status = FltAllocateContext( AesTestData.Filter,
                                 FLT_STREAMHANDLE_CONTEXT,
                                 sizeof(AESTEST_STREAM_HANDLE_CONTEXT),
                                 NonPagedPool,
                                 &StreamHandleContext );

    if (!NT_SUCCESS( Status )) {

        return Status;
    }

    //
    //  Initialize the newly created context
    //

    RtlZeroMemory( StreamHandleContext, sizeof(AESTEST_STREAM_HANDLE_CONTEXT) );

    *pStreamHandleContext = StreamHandleContext;

    return STATUS_SUCCESS;
}

NTSTATUS
FindOrCreateStreamHandleContext (
    PFLT_CALLBACK_DATA Cbd,
    BOOLEAN CreateIfNotFound,
    PAESTEST_STREAM_HANDLE_CONTEXT *pStreamHandleContext,
    PBOOLEAN ContextCreated
    )
{
    NTSTATUS Status;
    PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext;
    PAESTEST_STREAM_HANDLE_CONTEXT OldStreamHandleContext;

    PAGED_CODE();

    *pStreamHandleContext = NULL;
    if (ContextCreated != NULL) *ContextCreated = FALSE;

    //
    //    First try to get the stream context.
    //

    Status = FltGetStreamHandleContext( Cbd->Iopb->TargetInstance,
                                        Cbd->Iopb->TargetFileObject,
                                        &StreamHandleContext );

    //
    //    If the call failed because the context does not exist
    //    and the user wants to creat a new one, the create a
    //    new context
    //

    if (!NT_SUCCESS( Status ) &&
        (Status == STATUS_NOT_FOUND) &&
        CreateIfNotFound) {


        //
        //    Create a stream context
        //

        Status = CreateStreamHandleContext( &StreamHandleContext );

        if (!NT_SUCCESS( Status )) {

            return Status;
        }


        //
        //    Set the new context we just allocated on the file object
        //

        Status = FltSetStreamHandleContext( Cbd->Iopb->TargetInstance,
                                            Cbd->Iopb->TargetFileObject,
                                            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                            StreamHandleContext,
                                            &OldStreamHandleContext );

        if (!NT_SUCCESS( Status )) {

            //
            //    We release the context here because FltSetStreamContext failed
            //
            //    If FltSetStreamContext succeeded then the context will be returned
            //    to the caller. The caller will use the context and then release it
            //    when he is done with the context.
            //

            FltReleaseContext( StreamHandleContext );

            if (Status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

                //
                //    FltSetStreamContext failed for a reason other than the context already
                //    existing on the stream. So the object now does not have any context set
                //    on it. So we return failure to the caller.
                //

                return Status;
            }

            //
            //    Race condition. Someone has set a context after we queried it.
            //    Use the already set context instead
            //

            //
            //    Return the existing context. Note that the new context that we allocated has already been
            //    realeased above.
            //

            StreamHandleContext = OldStreamHandleContext;
            Status = STATUS_SUCCESS;

        } else {

            if (ContextCreated != NULL) *ContextCreated = TRUE;
        }
    }

    *pStreamHandleContext = StreamHandleContext;

    return Status;
}

FLT_PREOP_CALLBACK_STATUS
AesTestPreCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{     
    UNREFERENCED_PARAMETER( Cbd );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
        
    PAGED_CODE();

    //
    //  Force a post-op callback so we can add our contexts to the opened 
    //  objects
    //

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
AesTestPostCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CbdContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{

    PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext = NULL;    
    NTSTATUS Status;
    BOOLEAN  StreamHandleContextCreated;
    POBJECT_NAME_INFORMATION NameInfo;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( CbdContext );

    PAGED_CODE();

    //
    //  If the Create has failed, do nothing
    //

    if (!NT_SUCCESS( Cbd->IoStatus.Status )) {
        
        goto PostCreateCleanup;        
    }

    Status = IoQueryFileDosDeviceName(Cbd->Iopb->TargetFileObject, &NameInfo);
    if (!NT_SUCCESS( Status )) {
        
        goto PostCreateCleanup;
    }

    if (_wcsnicmp(NameInfo->Name.Buffer, L"c:\\aestest.dat", wcslen(L"c:\\aestest.dat")) != 0) {
        
        goto PostCreateCleanup;
    }
    
    //
    // Find or create a stream context
    //

    Status = FindOrCreateStreamHandleContext(Cbd, 
                                             TRUE,
                                             &StreamHandleContext,
                                             &StreamHandleContextCreated);
    if (!NT_SUCCESS( Status )) {

        //
        //  This failure will most likely be because stream contexts are not supported
        //  on the object we are trying to assign a context to or the object is being 
        //  deleted
        //
    
        goto PostCreateCleanup;
    }

    if (StreamHandleContext->NameInfo != NULL) {

        ExFreePool(StreamHandleContext->NameInfo);
    }
    
    //
    //  Update the file name in the context
    //

    StreamHandleContext->NameInfo = NameInfo;

    use_aesni_if_present();
    aesni_init_ctx(Key, KEY_SIZE, &StreamHandleContext->ctx_ni);
    aesni_init_ctr_ctx(Key, KEY_SIZE, &StreamHandleContext->ctr_ctx_ni);

    no_use_aesni();
    aesni_init_ctx(Key, KEY_SIZE, &StreamHandleContext->ctx_no);
    aesni_init_ctr_ctx(Key, KEY_SIZE, &StreamHandleContext->ctr_ctx_no);

PostCreateCleanup:
    
    //
    // Release the references we have acquired
    //    

    if (StreamHandleContext != NULL) {

        FltReleaseContext( StreamHandleContext );
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
AesTestPreWrite (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext = NULL;    
    NTSTATUS Status;
    BOOLEAN  StreamHandleContextCreated;
    PUCHAR   Buffer;
    PUCHAR   CypherText = NULL;
    PUCHAR   PlainText  = NULL;
    ULONG    Length;
    LARGE_INTEGER Offset;

    LARGE_INTEGER StartTime;
    LONGLONG      ElapsedTime;
    UCHAR Notice[4] = {0xab, 0xcd, 0xef, 0x90};

    if (!FLT_IS_IRP_OPERATION(Cbd)) {
        goto PreWriteCleanup;
    }

    if (!FlagOn(Cbd->Iopb->IrpFlags, IRP_NOCACHE)) {
        goto PreWriteCleanup;
    }

    if (Cbd->Iopb->Parameters.Write.Length == 0) {
        goto PreWriteCleanup;
    }

    //
    //  Get the users buffer address.  If there is a MDL defined, use
    //  it.  If not use the given buffer address.
    //

    if (Cbd->Iopb->Parameters.Write.MdlAddress != NULL) {

        Buffer = MmGetSystemAddressForMdlSafe( Cbd->Iopb->Parameters.Write.MdlAddress,
                                               NormalPagePriority );

    } else {

        //
        //  Use the users buffer
        //

        Buffer  = Cbd->Iopb->Parameters.Write.WriteBuffer;
    }

    if (Buffer == NULL) {

        goto PreWriteCleanup;
    }

    //
    // Find or create a stream context
    //

    Status = FindOrCreateStreamHandleContext(Cbd, 
                                             FALSE,
                                             &StreamHandleContext,
                                             &StreamHandleContextCreated);
    if (!NT_SUCCESS( Status )) {

        //
        //  This failure will most likely be because stream contexts are not supported
        //  on the object we are trying to assign a context to or the object is being 
        //  deleted
        //
    
        goto PreWriteCleanup;
    }

    CypherText = ExAllocatePoolWithTag(NonPagedPool, Cbd->Iopb->Parameters.Write.Length, 'hpyc');
    PlainText  = ExAllocatePoolWithTag(NonPagedPool, Cbd->Iopb->Parameters.Write.Length, 'nalp');
    if (!CypherText || !PlainText) {
        goto PreWriteCleanup;
    }

    Offset = Cbd->Iopb->Parameters.Read.ByteOffset;
    Length = Cbd->Iopb->Parameters.Write.Length;

    StreamHandleContext->DataSize += Length;
    if (AesTestData.AesFlag & FLAG_AESNI) {

        use_aesni_if_present();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt(Key, KEY_SIZE, Buffer, CypherText, Length));

        ASSERT (AESNI_SUCCESS == aesni_decrypt(Key, KEY_SIZE, CypherText, PlainText, Length));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AESNI_Time += ElapsedTime;

        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));

        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctx(&StreamHandleContext->ctx_ni, Buffer, CypherText, Length));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctx(&StreamHandleContext->ctx_ni, CypherText, PlainText, Length));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AESNI_CTX_Time += ElapsedTime;
        
        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));
    }

    if (AesTestData.AesFlag & FLAG_AES) {

        no_use_aesni();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt(Key, KEY_SIZE, Buffer, CypherText, Length));

        ASSERT (AESNI_SUCCESS == aesni_decrypt(Key, KEY_SIZE, CypherText, PlainText, Length));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AES_Time += ElapsedTime;

        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));

        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctx(&StreamHandleContext->ctx_no, Buffer, CypherText, Length));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctx(&StreamHandleContext->ctx_no, CypherText, PlainText, Length));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AES_CTX_Time += ElapsedTime;
        
        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));
    }

    if (AesTestData.AesFlag & FLAG_AESNI_CTR) {
        
        use_aesni_if_present();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr(Key, KEY_SIZE, Buffer, CypherText, Offset.QuadPart, Length, Notice));

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText, PlainText, Offset.QuadPart, Length, Notice));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AESNI_CTR_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));

        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));

        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_ni, Buffer, CypherText, Offset.QuadPart, Length, Notice));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_ni, CypherText, PlainText, Offset.QuadPart, Length, Notice));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AESNI_CTR_CTX_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_ni, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));
        
        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));
    }

    if (AesTestData.AesFlag & FLAG_AES_CTR) {

        no_use_aesni();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr(Key, KEY_SIZE, Buffer, CypherText, Offset.QuadPart, Length, Notice));

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText, PlainText, Offset.QuadPart, Length, Notice));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AES_CTR_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));

        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));
        
        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_no, Buffer, CypherText, Offset.QuadPart, Length, Notice));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_no, CypherText, PlainText, Offset.QuadPart, Length, Notice));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AES_CTR_CTX_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_no, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));
        
        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));
    }

PreWriteCleanup:

    if (StreamHandleContext != NULL) {
        FltReleaseContext( StreamHandleContext );
    }

    if (CypherText) {
        ExFreePoolWithTag(CypherText, 'hpyc');
    }

    if (PlainText) {
        ExFreePoolWithTag(PlainText, 'nalp');
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
AesTestPreRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    NTSTATUS Status;
    PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext = NULL;    
    BOOLEAN  StreamHandleContextCreated;
    FLT_PREOP_CALLBACK_STATUS CbStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
 
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    if (!FLT_IS_IRP_OPERATION(Cbd)) {
        CbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!FlagOn(Cbd->Iopb->IrpFlags, IRP_NOCACHE)) {
        CbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Cbd->Iopb->Parameters.Read.Length == 0) {
        CbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Find or create a stream context
    //

    Status = FindOrCreateStreamHandleContext(Cbd, 
                                            FALSE,
                                            &StreamHandleContext,
                                            &StreamHandleContextCreated);
    if (NT_SUCCESS( Status )) {

        *CompletionContext = StreamHandleContext;
    } else {
        CbStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return CbStatus;
}

FLT_POSTOP_CALLBACK_STATUS
AesTestPostRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext = NULL;    
    NTSTATUS      Status;
    PUCHAR        Buffer;
    PUCHAR        CypherText = NULL;
    PUCHAR        PlainText  = NULL;
    ULONG         Length;
    LARGE_INTEGER Offset;

    LARGE_INTEGER StartTime;
    LONGLONG      ElapsedTime;
    UCHAR Notice[4] = {0xab, 0xcd, 0xef, 0x90};

    if (!NT_SUCCESS( Cbd->IoStatus.Status )) {
    
        goto PostReadCleanup;        
    }

    //
    //  Get the users buffer address.  If there is a MDL defined, use
    //  it.  If not use the given buffer address.
    //

    if (Cbd->Iopb->Parameters.Read.MdlAddress != NULL) {

        Buffer = MmGetSystemAddressForMdlSafe( Cbd->Iopb->Parameters.Read.MdlAddress,
                                               NormalPagePriority );

    } else {

        //
        //  Use the users buffer
        //

        Buffer  = Cbd->Iopb->Parameters.Read.ReadBuffer;
    }

    if (Buffer == NULL) {

        goto PostReadCleanup;
    }

    StreamHandleContext = (PAESTEST_STREAM_HANDLE_CONTEXT)CompletionContext;

    CypherText = ExAllocatePoolWithTag(NonPagedPool, Cbd->Iopb->Parameters.Read.Length, 'hpyc');
    PlainText  = ExAllocatePoolWithTag(NonPagedPool, Cbd->Iopb->Parameters.Read.Length, 'nalp');
    if (!CypherText || !PlainText) {
        goto PostReadCleanup;
    }

    Offset = Cbd->Iopb->Parameters.Read.ByteOffset;
    Length = Cbd->Iopb->Parameters.Read.Length;
    StreamHandleContext->DataSize += Length;
    if (AesTestData.AesFlag & FLAG_AESNI) {

        use_aesni_if_present();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt(Key, KEY_SIZE, Buffer, CypherText, Length));

        ASSERT (AESNI_SUCCESS == aesni_decrypt(Key, KEY_SIZE, CypherText, PlainText, Length));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AESNI_Time += ElapsedTime;

        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));

        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctx(&StreamHandleContext->ctx_ni, Buffer, CypherText, Length));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctx(&StreamHandleContext->ctx_ni, CypherText, PlainText, Length));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AESNI_CTX_Time += ElapsedTime;
        
        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));
    }

    if (AesTestData.AesFlag & FLAG_AES) {

        no_use_aesni();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt(Key, KEY_SIZE, Buffer, CypherText, Length));

        ASSERT (AESNI_SUCCESS == aesni_decrypt(Key, KEY_SIZE, CypherText, PlainText, Length));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AES_Time += ElapsedTime;

        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));

        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctx(&StreamHandleContext->ctx_no, Buffer, CypherText, Length));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctx(&StreamHandleContext->ctx_no, CypherText, PlainText, Length));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AES_CTX_Time += ElapsedTime;
        
        ASSERT (Length == RtlCompareMemory(Buffer, PlainText, Length));
    }

    if (AesTestData.AesFlag & FLAG_AESNI_CTR) {
        
        use_aesni_if_present();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr(Key, KEY_SIZE, Buffer, CypherText, Offset.QuadPart, Length, Notice));

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText, PlainText, Offset.QuadPart, Length, Notice));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AESNI_CTR_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));

        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));

        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_ni, Buffer, CypherText, Offset.QuadPart, Length, Notice));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_ni, CypherText, PlainText, Offset.QuadPart, Length, Notice));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AESNI_CTR_CTX_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_ni, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));
        
        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));
    }

    if (AesTestData.AesFlag & FLAG_AES_CTR) {

        no_use_aesni();

        GetElapsedTimeInit(&StartTime);

        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr(Key, KEY_SIZE, Buffer, CypherText, Offset.QuadPart, Length, Notice));

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText, PlainText, Offset.QuadPart, Length, Notice));

        ElapsedTime = GetElapsedTime(&StartTime);

        StreamHandleContext->AES_CTR_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr(Key, KEY_SIZE, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));

        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));
        
        GetElapsedTimeInit(&StartTime);
        
        ASSERT (AESNI_SUCCESS == aesni_encrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_no, Buffer, CypherText, Offset.QuadPart, Length, Notice));
        
        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_no, CypherText, PlainText, Offset.QuadPart, Length, Notice));
        
        ElapsedTime = GetElapsedTime(&StartTime);
        
        StreamHandleContext->AES_CTR_CTX_Time += ElapsedTime;

        ASSERT (AESNI_SUCCESS == aesni_decrypt_ctr_ctx(&StreamHandleContext->ctr_ctx_no, CypherText + 1, PlainText, Offset.QuadPart + 1, Length - 1, Notice));
        
        ASSERT (Length - 1 == RtlCompareMemory(Buffer + 1, PlainText, Length - 1));
    }

PostReadCleanup:

    if (StreamHandleContext != NULL) {
        FltReleaseContext( StreamHandleContext );
    }

    if (CypherText) {
        ExFreePoolWithTag(CypherText, 'hpyc');
    }

    if (PlainText) {
        ExFreePoolWithTag(PlainText, 'nalp');
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
AesTestPreClose (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    PAESTEST_STREAM_HANDLE_CONTEXT StreamHandleContext = NULL;    
    NTSTATUS Status;
    BOOLEAN  StreamHandleContextCreated;

    //
    // Find or create a stream context
    //

    Status = FindOrCreateStreamHandleContext(Cbd, 
                                             FALSE,
                                             &StreamHandleContext,
                                             &StreamHandleContextCreated);
    if (!NT_SUCCESS( Status )) {

        //
        //  This failure will most likely be because stream contexts are not supported
        //  on the object we are trying to assign a context to or the object is being 
        //  deleted
        //
    
        goto PreCloseCleanup;
    }

    if (StreamHandleContext->DataSize == 0) {

        goto PreCloseCleanup;
    }

    DbgPrint("[%wZ], DataSize: %u\n", &StreamHandleContext->NameInfo->Name, StreamHandleContext->DataSize);

    StreamHandleContext->DataSize;
    if (AesTestData.AesFlag & FLAG_AESNI) {

        DbgPrint("    [AESNI], ElapsedTime: %u us\n", StreamHandleContext->AESNI_Time);
        DbgPrint("    [AESNI CTX], ElapsedTime: %u us\n", StreamHandleContext->AESNI_CTX_Time);
    }

    if (AesTestData.AesFlag & FLAG_AESNI_CTR) {

        DbgPrint("    [AESNI_CTR], ElapsedTime: %u us\n", StreamHandleContext->AESNI_CTR_Time);
        DbgPrint("    [AESNI_CTR CTX], ElapsedTime: %u us\n", StreamHandleContext->AESNI_CTR_CTX_Time);
    }

    if (AesTestData.AesFlag & FLAG_AES) {

        DbgPrint("    [AES], ElapsedTime: %u us\n", StreamHandleContext->AES_Time);
        DbgPrint("    [AES CTX], ElapsedTime: %u us\n", StreamHandleContext->AES_CTX_Time);
    }

    if (AesTestData.AesFlag & FLAG_AES_CTR) {

        DbgPrint("    [AES_CTR], ElapsedTime: %u us\n", StreamHandleContext->AES_CTR_Time);
        DbgPrint("    [AES_CTR CTX], ElapsedTime: %u us\n", StreamHandleContext->AES_CTR_CTX_Time);
    }

PreCloseCleanup:

    if (StreamHandleContext != NULL) {
        FltReleaseContext( StreamHandleContext );
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
