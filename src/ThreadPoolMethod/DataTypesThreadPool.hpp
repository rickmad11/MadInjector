#pragma once

#ifdef _WIN64

//https://github.com/winsiderss/systeminformer
//https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h

#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
    STANDARD_RIGHTS_REQUIRED | \
    WORKER_FACTORY_RELEASE_WORKER | \
    WORKER_FACTORY_WAIT | \
    WORKER_FACTORY_SET_INFORMATION | \
    WORKER_FACTORY_QUERY_INFORMATION | \
    WORKER_FACTORY_READY_WORKER | \
    WORKER_FACTORY_SHUTDOWN \
    )

typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout, // LARGE_INTEGER
    WorkerFactoryRetryTimeout, // LARGE_INTEGER
    WorkerFactoryIdleTimeout, // s: LARGE_INTEGER
    WorkerFactoryBindingCount, // s: ULONG
    WorkerFactoryThreadMinimum, // s: ULONG
    WorkerFactoryThreadMaximum, // s: ULONG
    WorkerFactoryPaused, // ULONG or BOOLEAN
    WorkerFactoryBasicInformation, // q: WORKER_FACTORY_BASIC_INFORMATION
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation, // 10
    WorkerFactoryThreadBasePriority, // s: ULONG
    WorkerFactoryTimeoutWaiters, // s: ULONG, since THRESHOLD
    WorkerFactoryFlags, // s: ULONG
    WorkerFactoryThreadSoftMaximum, // s: ULONG
    WorkerFactoryThreadCpuSets, // since REDSTONE5
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI*NtQueryInformationWorkerFactory)(
    __in  HANDLE WorkerFactoryHandle,
    __in  WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    __out PVOID WorkerFactoryInformation,
    __in  ULONG WorkerFactoryInformationLength,
    __out_opt PULONG ReturnLength
);

typedef NTSTATUS (NTAPI*NtSetInformationWorkerFactory)(
    __in HANDLE WorkerFactoryHandle,
    __in WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    __in PVOID WorkerFactoryInformation,
    __in ULONG WorkerFactoryInformationLength
);

typedef NTSTATUS(NTAPI *NtCreateWorkerFactory)(
    __out PHANDLE WorkerFactoryHandleReturn,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE CompletionPortHandle,
    __in HANDLE WorkerProcessHandle,
    __in PVOID StartRoutine,
    __in_opt PVOID StartParameter,
    __in_opt ULONG MaxThreadCount,
    __in_opt SIZE_T StackReserve,
    __in_opt SIZE_T StackCommit
);

//https://github.com/SafeBreach-Labs/PoolParty/blob/main/PoolParty/ThreadPool.hpp
//https://github.com/Uri3n/Thread-Pool-Injection-PoC/tree/main/ThreadPoolInjection/include

typedef struct _TP_TASK_CALLBACKS
{
    void* ExecuteCallback;
    void* Unposted;
} TP_TASK_CALLBACKS, * PTP_TASK_CALLBACKS;

typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, * PTP_TASK;

typedef struct _TPP_REFCOUNT
{
    volatile INT32 Refcount;
} TPP_REFCOUNT, * PTPP_REFCOUNT;

typedef struct _TPP_CALLER
{
    void* ReturnAddress;
} TPP_CALLER, * PTPP_CALLER;

typedef struct _TPP_PH
{
    struct _TPP_PH_LINKS* Root;
} TPP_PH, * PTPP_PH;

typedef struct _TP_DIRECT
{
    struct _TP_TASK Task;
    UINT64 Lock;
    struct _LIST_ENTRY IoCompletionInformationList;
    void* Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char __PADDING__[3];
} TP_DIRECT, * PTP_DIRECT;

typedef struct _TPP_TIMER_SUBQUEUE
{
    INT64 Expiration;
    struct _TPP_PH WindowStart;
    struct _TPP_PH WindowEnd;
    void* Timer;
    void* TimerPkt;
    struct _TP_DIRECT Direct;
    UINT32 ExpirationWindow;
    INT32 __PADDING__[1];
} TPP_TIMER_SUBQUEUE, * PTPP_TIMER_SUBQUEUE;

typedef struct _TPP_TIMER_QUEUE
{
    struct _RTL_SRWLOCK Lock;
    struct _TPP_TIMER_SUBQUEUE AbsoluteQueue;
    struct _TPP_TIMER_SUBQUEUE RelativeQueue;
    INT32 AllocatedTimerCount;
    INT32 __PADDING__[1];
} TPP_TIMER_QUEUE, * PTPP_TIMER_QUEUE;

typedef struct _TPP_NUMA_NODE
{
    INT32 WorkerCount;
} TPP_NUMA_NODE, * PTPP_NUMA_NODE;

typedef union _TPP_POOL_QUEUE_STATE
{
    union
    {
        INT64 Exchange;
        struct
        {
            INT32 RunningThreadGoal : 16;
            UINT32 PendingReleaseCount : 16;
            UINT32 QueueLength;
        };
    };
} TPP_POOL_QUEUE_STATE, * PTPP_POOL_QUEUE_STATE;

typedef struct _TPP_QUEUE
{
    struct _LIST_ENTRY Queue;
    struct _RTL_SRWLOCK Lock;
} TPP_QUEUE, * PTPP_QUEUE;

typedef struct _FULL_TP_POOL
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_239;
    union _TPP_POOL_QUEUE_STATE QueueState;
    struct _TPP_QUEUE* TaskQueue[3];
    struct _TPP_NUMA_NODE* NumaNode;
    struct _GROUP_AFFINITY* ProximityInfo;
    void* WorkerFactory;
    void* CompletionPort;
    struct _RTL_SRWLOCK Lock;
    struct _LIST_ENTRY PoolObjectList;
    struct _LIST_ENTRY WorkerList;
    struct _TPP_TIMER_QUEUE TimerQueue;
    struct _RTL_SRWLOCK ShutdownLock;
    UINT8 ShutdownInitiated;
    UINT8 Released;
    UINT16 PoolFlags;
    long Padding_240;
    struct _LIST_ENTRY PoolLinks;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    volatile INT32 AvailableWorkerCount;
    volatile INT32 LongRunningWorkerCount;
    UINT32 LastProcCount;
    volatile INT32 NodeStatus;
    volatile INT32 BindingCount;
    UINT32 CallbackChecksDisabled : 1;
    UINT32 TrimTarget : 11;
    UINT32 TrimmedThrdCount : 11;
    UINT32 SelectedCpuSetCount;
    long Padding_241;
    struct _RTL_CONDITION_VARIABLE TrimComplete;
    struct _LIST_ENTRY TrimmedWorkerList;
} FULL_TP_POOL, * PFULL_TP_POOL;

typedef struct _ALPC_WORK_ON_BEHALF_TICKET
{
    UINT32 ThreadId;
    UINT32 ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

typedef union _TPP_WORK_STATE
{
    union
    {
        INT32 Exchange;
        UINT32 Insertable : 1;
        UINT32 PendingCallbackCount : 31;
    };
} TPP_WORK_STATE, * PTPP_WORK_STATE;

typedef struct _TPP_ITE_WAITER
{
    struct _TPP_ITE_WAITER* Next;
    void* ThreadId;
} TPP_ITE_WAITER, * PTPP_ITE_WAITER;

typedef struct _TPP_PH_LINKS
{
    struct _LIST_ENTRY Siblings;
    struct _LIST_ENTRY Children;
    INT64 Key;
} TPP_PH_LINKS, * PTPP_PH_LINKS;

typedef struct _TPP_ITE
{
    struct _TPP_ITE_WAITER* First;
} TPP_ITE, * PTPP_ITE;

typedef union _TPP_FLAGS_COUNT
{
    union
    {
        UINT64 Count : 60;
        UINT64 Flags : 4;
        INT64 Data;
    };
} TPP_FLAGS_COUNT, * PTPP_FLAGS_COUNT;

typedef struct _TPP_BARRIER
{
    volatile union _TPP_FLAGS_COUNT Ptr;
    struct _RTL_SRWLOCK WaitLock;
    struct _TPP_ITE WaitList;
} TPP_BARRIER, * PTPP_BARRIER;

typedef struct _TP_CLEANUP_GROUP
{
    struct _TPP_REFCOUNT Refcount;
    INT32 Released;
    struct _RTL_SRWLOCK MemberLock;
    struct _LIST_ENTRY MemberList;
    struct _TPP_BARRIER Barrier;
    struct _RTL_SRWLOCK CleanupLock;
    struct _LIST_ENTRY CleanupList;
} TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;


typedef struct _TPP_CLEANUP_GROUP_MEMBER
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_233;
    const struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS* VFuncs;
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    void* CleanupGroupCancelCallback;
    void* FinalizationCallback;
    struct _LIST_ENTRY CleanupGroupMemberLinks;
    struct _TPP_BARRIER CallbackBarrier;
    union
    {
        void* Callback;
        void* WorkCallback;
        void* SimpleCallback;
        void* TimerCallback;
        void* WaitCallback;
        void* IoCallback;
        void* AlpcCallback;
        void* AlpcCallbackEx;
        void* JobCallback;
    };
    void* Context;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    void* SubProcessTag;
    struct _GUID ActivityId;
    struct _ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    void* RaceDll;
    FULL_TP_POOL* Pool;
    struct _LIST_ENTRY PoolObjectLinks;
    union
    {
        volatile INT32 Flags;
        UINT32 LongFunction : 1;
        UINT32 Persistent : 1;
        UINT32 UnusedPublic : 14;
        UINT32 Released : 1;
        UINT32 CleanupGroupReleased : 1;
        UINT32 InCleanupGroupCleanupList : 1;
        UINT32 UnusedPrivate : 13;
    };
    long Padding_234;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    enum _TP_CALLBACK_PRIORITY CallbackPriority;
    INT32 __PADDING__[1];
} TPP_CLEANUP_GROUP_MEMBER, * PTPP_CLEANUP_GROUP_MEMBER;

typedef struct _FULL_TP_WORK
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_TASK Task;
    volatile union _TPP_WORK_STATE WorkState;
    INT32 __PADDING__[1];
} FULL_TP_WORK, * PFULL_TP_WORK;

typedef struct _FULL_TP_TIMER
{
    struct _FULL_TP_WORK Work;
    struct _RTL_SRWLOCK Lock;
    union
    {
        struct _TPP_PH_LINKS WindowEndLinks;
        struct _LIST_ENTRY ExpirationLinks;
    };
    struct _TPP_PH_LINKS WindowStartLinks;
    INT64 DueTime;
    struct _TPP_ITE Ite;
    UINT32 Window;
    UINT32 Period;
    UINT8 Inserted;
    UINT8 WaitTimer;
    union
    {
        UINT8 TimerStatus;
        UINT8 InQueue : 1;
        UINT8 Absolute : 1;
        UINT8 Cancelled : 1;
    };
    UINT8 BlockInsert;
    INT32 __PADDING__[1];
} FULL_TP_TIMER, * PFULL_TP_TIMER;

typedef struct _FULL_TP_WAIT
{
    struct _FULL_TP_TIMER Timer;
    void* Handle;
    void* WaitPkt;
    void* NextWaitHandle;
    union _LARGE_INTEGER NextWaitTimeout;
    struct _TP_DIRECT Direct;
    union
    {
        union
        {
            UINT8 AllFlags;
            UINT8 NextWaitActive : 1;
            UINT8 NextTimeoutActive : 1;
            UINT8 CallbackCounted : 1;
            UINT8 Spare : 5;
        };
    } WaitFlags;
    char __PADDING__[7];
} FULL_TP_WAIT, * PFULL_TP_WAIT;

typedef struct _FULL_TP_IO
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_DIRECT Direct;
    void* File;
    volatile INT32 PendingIrpCount;
    INT32 __PADDING__[1];
} FULL_TP_IO, * PFULL_TP_IO;

typedef struct _FULL_TP_ALPC
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* AlpcPort;
    INT32 DeferredSendCount;
    INT32 LastConcurrencyCount;
    union
    {
        UINT32 Flags;
        UINT32 ExTypeCallback : 1;
        UINT32 CompletionListRegistered : 1;
        UINT32 Reserved : 30;
    };
    INT32 __PADDING__[1];
} FULL_TP_ALPC, * PFULL_TP_ALPC;

typedef struct _FULL_TP_JOB
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* JobHandle;
    union
    {
        volatile int64_t CompletionState;
        int64_t Rundown : 1;
        int64_t CompletionCount : 63;
    };
    struct _RTL_SRWLOCK RundownLock;
} FULL_TP_JOB, * PFULL_TP_JOB;

typedef struct _T2_SET_PARAMETERS_V0
{
    ULONG Version;
    ULONG Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FilePipeInformation = 23,
    FilePipeLocalInformation = 24,
    FilePipeRemoteInformation = 25,
    FileMailslotQueryInformation = 26,
    FileMailslotSetInformation = 27,
    FileCompressionInformation = 28,
    FileObjectIdInformation = 29,
    FileCompletionInformation = 30,
    FileMoveClusterInformation = 31,
    FileQuotaInformation = 32,
    FileReparsePointInformation = 33,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileTrackingInformation = 36,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
    FileValidDataLengthInformation = 39,
    FileShortNameInformation = 40,
    FileIoCompletionNotificationInformation = 41,
    FileIoStatusBlockRangeInformation = 42,
    FileIoPriorityHintInformation = 43,
    FileSfioReserveInformation = 44,
    FileSfioVolumeInformation = 45,
    FileHardLinkInformation = 46,
    FileProcessIdsUsingFileInformation = 47,
    FileNormalizedNameInformation = 48,
    FileNetworkPhysicalNameInformation = 49,
    FileIdGlobalTxDirectoryInformation = 50,
    FileIsRemoteDeviceInformation = 51,
    FileUnusedInformation = 52,
    FileNumaNodeInformation = 53,
    FileStandardLinkInformation = 54,
    FileRemoteProtocolInformation = 55,
    FileRenameInformationBypassAccessCheck = 56,
    FileLinkInformationBypassAccessCheck = 57,
    FileVolumeNameInformation = 58,
    FileIdInformation = 59,
    FileIdExtdDirectoryInformation = 60,
    FileReplaceCompletionInformation = 61,
    FileHardLinkFullIdInformation = 62,
    FileIdExtdBothDirectoryInformation = 63,
    FileDispositionInformationEx = 64,
    FileRenameInformationEx = 65,
    FileRenameInformationExBypassAccessCheck = 66,
    FileDesiredStorageClassInformation = 67,
    FileStatInformation = 68,
    FileMemoryPartitionInformation = 69,
    FileStatLxInformation = 70,
    FileCaseSensitiveInformation = 71,
    FileLinkInformationEx = 72,
    FileLinkInformationExBypassAccessCheck = 73,
    FileStorageReserveIdInformation = 74,
    FileCaseSensitiveInformationForceAccessCheck = 75,
    FileKnownFolderInformation = 76,
    FileStatBasicInformation = 77,
    FileId64ExtdDirectoryInformation = 78,
    FileId64ExtdBothDirectoryInformation = 79,
    FileIdAllExtdDirectoryInformation = 80,
    FileIdAllExtdBothDirectoryInformation = 81,
    FileStreamReservationInformation,
    FileMupProviderInfo,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID  Key;
} FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;

typedef struct _ALPC_PORT_ATTRIBUTES
{
    unsigned long Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    unsigned __int64 MaxMessageLength;
    unsigned __int64 MemoryBandwidth;
    unsigned __int64 MaxPoolUsage;
    unsigned __int64 MaxSectionSize;
    unsigned __int64 MaxViewSize;
    unsigned __int64 MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
    AlpcBasicInformation, // q: out ALPC_BASIC_INFORMATION
    AlpcPortInformation, // s: in ALPC_PORT_ATTRIBUTES
    AlpcAssociateCompletionPortInformation, // s: in ALPC_PORT_ASSOCIATE_COMPLETION_PORT
    AlpcConnectedSIDInformation, // q: in SID
    AlpcServerInformation, // q: inout ALPC_SERVER_INFORMATION
    AlpcMessageZoneInformation, // s: in ALPC_PORT_MESSAGE_ZONE_INFORMATION
    AlpcRegisterCompletionListInformation, // s: in ALPC_PORT_COMPLETION_LIST_INFORMATION
    AlpcUnregisterCompletionListInformation, // s: VOID
    AlpcAdjustCompletionListConcurrencyCountInformation, // s: in ULONG
    AlpcRegisterCallbackInformation, // kernel-mode only
    AlpcCompletionListRundownInformation, // s: VOID
    MaxAlpcPortInfoClass
} ALPC_PORT_INFORMATION_CLASS;

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;

typedef struct _ALPC_MESSAGE {
    PORT_MESSAGE PortHeader;
    BYTE PortMessage[1000];
} ALPC_MESSAGE, * PALPC_MESSAGE;

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
{
    PVOID CompletionKey;
    HANDLE CompletionPort;
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

typedef NTSTATUS(NTAPI* TpAllocJobNotification)(
     PFULL_TP_JOB* JobReturn, 
     HANDLE HJob, 
     PVOID Callback, PVOID Context, 
     PTP_CALLBACK_ENVIRON CallbackEnviron);

typedef NTSTATUS(NTAPI* TpReleaseJobNotification)(PVOID Job);

typedef NTSTATUS(NTAPI* NtSetIoCompletion)(
	HANDLE IoCompletionHandle,
	PVOID CompletionKey,
    NTSTATUS IoStatusBlock,
    NTSTATUS CompletionStatus,
    ULONG NumberOfBytesTransfered);

typedef NTSTATUS (NTAPI*NtAssociateWaitCompletionPacket)(
    _In_ HANDLE WaitCompletionPacketHandle,
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE TargetObjectHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation,
    _Out_opt_ PBOOLEAN AlreadySignaled
);

typedef NTSTATUS
(NTAPI* NtSetTimer2)(
    __in HANDLE TimerHandle,
    __in PLARGE_INTEGER DueTime,
    __in_opt PLARGE_INTEGER Period,
    __in PT2_SET_PARAMETERS Parameters
);

typedef NTSTATUS (NTAPI*NtCancelTimer2)(
    HANDLE TimerHandle,
    PVOID Parameters
);

typedef NTSTATUS (NTAPI *NtSetInformationFile)(
    IN HANDLE               FileHandle,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    IN PVOID                FileInformation,
    IN ULONG                Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS(NTAPI*NtQueryInformationFile)(
    HANDLE                 FileHandle,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS(NTAPI* NtAlpcCreatePort)(
    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
    );

typedef NTSTATUS(NTAPI* NtAlpcDisconnectPort)(
    PVOID PortHandle,
    bool LSB_Flag // checks if LSB is set or not then does some stuff
    );

typedef VOID(NTAPI* PTP_ALPC_CALLBACK)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID Context,
    _In_ PFULL_TP_ALPC Alpc
    );

typedef NTSTATUS(NTAPI* TpAllocAlpcCompletion)(
    _Out_ PFULL_TP_ALPC* AlpcReturn,
    _In_ HANDLE AlpcPort,
    _In_ PTP_ALPC_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

typedef NTSTATUS(NTAPI* NtAlpcSetInformation)(
    _In_ HANDLE PortHandle,
    _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    _In_reads_bytes_opt_(Length) PVOID PortInformation,
    _In_ ULONG Length
    );

typedef NTSTATUS(NTAPI* NtAlpcConnectPort)(
    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_ DWORD ConnectionFlags,
    _In_opt_ PSID RequiredServerSid,
    _In_opt_ PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PSIZE_T ConnectMessageSize,
    _In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    _In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
    );

namespace oThreadPool
{
    struct ShellcodeData {

        ShellcodeData() = default;

        ShellcodeData(void* pFunc, void* pArgs, HANDLE process_handle);

        ShellcodeData(void* pFunc, void* pArgs, HANDLE process_handle, DWORD64 fSize, void* pfAny);

        ~ShellcodeData()
        {
            if (has_function)
                Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_shellcode, allocated_args, allocated_function);
            else
                Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_shellcode);
        }

        void* pFunc = nullptr;
        void* pArgs = nullptr;
        HANDLE const process_handle = nullptr;
        const DWORD64 function_size = 0;
        void* const pfAny = nullptr;
        bool internal_error = false;
        bool has_function = false;

        BYTE shellcode[85] =
        {
            //there are multiple ways of doing this simplest ones are this and another allocation then storing the addresses into the array before writing it
            0xE9, 0x10, 0x00, 0x00, 0x00, // skip our data part
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sizeof(ShellcodeData) x64
            0x50,																	// push rax
            0x51,																	// push rcx
            0x52,																	// push rdx
            0x41, 0x50,																// push r8
            0x41, 0x51,																// push r9
            0x41, 0x52,																// push r10
            0x41, 0x53,		// push	all volatile registers							// push r11
            0x9C,																	// pushf push all EFLAGS 
            0x53,																	// push rbx
            0x48, 0x8D, 0x1D, 0xDC, 0xFF, 0xFF, 0xFF,								// lea rbx, [rip - sizeof(ShellcodeData) - 20 -> this entire instr is 7 bytes and the ones before are 13 bytes]
            0x55,																	// push rbp
            0x48, 0x89, 0xE5,														// mov rbp, rsp
            0x48, 0x83, 0xE4, 0xF0,													// and rsp, -0x10 (align rsp to 16 bytes) 
            0x48, 0x8B, 0x4B, 0x08,													// mov rcx, QWORD [rbx + 0x8]
            0x48, 0x83, 0xEC, 0x20,													// sub rsp,0x20 shadow space
            0xFF, 0x53, 0x00,														// call qword ptr [rbx + 0x0]
            0x48, 0x83, 0xC4, 0x20,													// add rsp,0x20 shadow space
            0x48, 0x31, 0xC0,														// xor rax, rax
            0x48, 0x89, 0xEC,														// mov rsp, rbp
            0x5D,																	// pop rbp
            0x5b,																	// pop rbx
            0x9D,																	// popfq pop all EFLAGS			
            0x41, 0x5B,																// pop r11
            0x41, 0x5A,																// pop r10
            0x41, 0x59,																// pop r9
            0x41, 0x58,																// pop r8
            0x5A,																	// pop rdx
            0x59,																	// pop rcx
            0x58,		// pop all volatile registers								// pop rax
            0xC3																	// ret
        };

        void* allocated_args = nullptr;
        void* allocated_function = nullptr;
        void* allocated_shellcode = nullptr;

        struct POOL_DATA
        {
            void* pFunction = nullptr;
            void* pArgs = nullptr;
            decltype(SuspendThread)* pfSuspendThread = nullptr;
            decltype(GetCurrentThread)* pfGetCurrentThread = nullptr;
            decltype(GetCurrentThreadId)* pfGetCurrentThreadId = nullptr;
            DWORD thread_id = 0;
        }pool_data;

    };
}

#endif