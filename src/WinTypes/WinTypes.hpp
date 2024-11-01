#pragma once
//https://ntdoc.m417z.com/
//https://github.com/paskalian/WID_LoadLibrary/tree/main
//https://www.geoffchappell.com/
//https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntldr.h

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // might lead to issues
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

#pragma region STRUCTS
//------------------------------------------------------------------------------------------------------
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	struct _SINGLE_LIST_ENTRY* Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE : int
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE, * PLDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union
	{
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		};
	};

	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef enum _LDR_DLL_LOAD_REASON : int
{
	LoadReasonUnknown = -1,
	LoadReasonStaticDependency = 0,
	LoadReasonStaticForwarderDependency = 1,
	LoadReasonDynamicForwarderDependency = 2,
	LoadReasonDelayloadDependency = 3,
	LoadReasonDynamicLoad = 4,
	LoadReasonAsImageLoad = 5,
	LoadReasonAsDataLoad = 6,
	LoadReasonEnclavePrimary = 7,
	LoadReasonEnclaveDependency = 8,
	LoadReasonPatchImage = 9
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE
{
	LdrHotPatchBaseImage = 0,
	LdrHotPatchNotApplied = 1,
	LdrHotPatchAppliedReverse = 2,
	LdrHotPatchAppliedForward = 3,
	LdrHotPatchFailedToPatch = 4,
	LdrHotPatchStateMax = 5
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ChpeEmulatorImage : 1;
			ULONG ReservedFlags5 : 1;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	PVOID EntryPointActivationContext;
	PVOID Lock; // RtlAcquireSRWLockExclusive
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	PVOID LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason; // since WIN8
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount; // since WIN10
	ULONG DependentLoadFlags;
	UCHAR SigningLevel; // since REDSTONE2
	ULONG CheckSum; // since 22H1
	PVOID ActivePatchImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef __declspec(align(4)) struct _SINGLE_LIST_ENTRY_32
{
	DWORD Next; // -> SINGLE_LIST_ENTRY_32
} SINGLE_LIST_ENTRY_32, * PSINGLE_LIST_ENTRY_32;

typedef __declspec(align(4)) struct _UNICODE_STRING_32
{
	WORD	Length;
	WORD	MaxLength;
	DWORD	szBuffer;
} UNICODE_STRING_32, * PUNICODE_STRING_32;

typedef __declspec(align(4)) struct _RTL_BALANCED_NODE_32
{
	union
	{
		DWORD Children[2];
		struct
		{
			DWORD Left;
			DWORD Right;
		};
	};

	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		DWORD ParentValue;
	};
} RTL_BALANCED_NODE_32, * PRTL_BALANCED_NODE_32;

typedef __declspec(align(4)) struct _LDR_DDAG_NODE_WIN11_32
{
	LIST_ENTRY32			Modules;
	DWORD					ServiceTagList; // -> LDR_SERVICE_TAG_RECORD_32
	ULONG					LoadCount;
	ULONG					LoadWhileUnloadingCount;
	ULONG					LowestLink;
	DWORD					Dependencies; // -> LDRP_CSLIST_32
	DWORD					IncomingDependencies; // -> LDRP_CSLIST_32
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY_32	CondenseLink;
	ULONG					PreorderNumber;
} LDR_DDAG_NODE_32, * PLDR_DDAG_NODE_32;

typedef struct _LDR_DATA_TABLE_ENTRY_32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;

	DWORD DllBase;
	DWORD EntryPoint;
	ULONG SizeOfImage;

	UNICODE_STRING_32 FullDllName;
	UNICODE_STRING_32 BaseDllName;

	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;

		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ReservedFlags5 : 2;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};

	WORD ObsoleteLoadCount;
	WORD TlsIndex;

	LIST_ENTRY32 HashLinks;

	ULONG TimedateStamp;
	DWORD EntryPointActivationContext;
	DWORD Spare;

	DWORD DdagNode; // -> LDR_DDAG_NODE_WIN11_32

	LIST_ENTRY32	NodeModuleLink;
	DWORD			LoadContext;
	DWORD			ParentDllBase;
	DWORD			SwitchBackContext;

	RTL_BALANCED_NODE_32 BaseAddressIndexNode;
	RTL_BALANCED_NODE_32 MappingInfoIndexNode;

	DWORD				OriginalBase;
	LARGE_INTEGER		LoadTime;
	ULONG				BaseNameHashValue;
	LDR_DLL_LOAD_REASON	LoadReason;
	ULONG				ImplicitPathOptions;

	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;

	ULONG CheckSum;
	DWORD ActivePathImageBase;
	LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY_32, * PLDR_DATA_TABLE_ENTRY_32;

typedef __declspec(align(4)) union _LDRP_LOAD_CONTEXT_FLAGS_32
{
	ULONG32 Flags;
	struct
	{
		ULONG32 Redirected : 1;
		ULONG32 BaseNameOnly : 1;
		ULONG32 HasFullPath : 1;
		ULONG32 KnownDll : 1;
		ULONG32 SystemImage : 1;
		ULONG32 ExecutableImage : 1;
		ULONG32 AppContainerImage : 1;
		ULONG32 CallInit : 1;
		ULONG32 UserAllocated : 1;
		ULONG32 SearchOnlyFirstPathSegment : 1;
		ULONG32 RedirectedByAPISet : 1;
	};
} LDRP_LOAD_CONTEXT_FLAGS_32, * PLDRP_LOAD_CONTEXT_FLAGS_32;

typedef __declspec(align(4)) struct _LDRP_PATH_SEARCH_CONTEXT_32 
{
	DWORD DllSearchPathOut; // wchar_t *
	DWORD unknown_0[3];
	DWORD OriginalFullDllName; // wchar_t *
	DWORD unknown_1[15];
} LDRP_PATH_SEARCH_CONTEXT_32, * PLDRP_PATH_SEARCH_CONTEXT_32;

typedef struct _LDRP_PATH_SEARCH_CONTEXT
{
	wchar_t* DllSearchPathOut;
	void* Unknown_0[3];
	wchar_t* OriginalFullDllName;
	void* unknown_1[7];
	ULONG64		unknown_2[4];
} LDRP_PATH_SEARCH_CONTEXT, * PLDRP_PATH_SEARCH_CONTEXT;

typedef union _LDRP_LOAD_CONTEXT_FLAGS
{
	ULONG32 Flags;
	struct 
	{
		ULONG32 Redirected : 1;
		ULONG32 Static : 1;
		ULONG32 BaseNameOnly : 1;
		ULONG32 HasFullPath : 1;
		ULONG32 KnownDll : 1;
		ULONG32 SystemImage : 1;
		ULONG32 ExecutableImage : 1;
		ULONG32 AppContainerImage : 1;
		ULONG32 CallInit : 1;
		ULONG32 UserAllocated : 1;
		ULONG32 SearchOnlyFirstPathSegment : 1;
		ULONG32 RedirectedByAPISet : 1;
	};
} LDRP_LOAD_CONTEXT_FLAGS, * PLDRP_LOAD_CONTEXT_FLAGS;

#ifdef _WIN64
typedef struct _LDRP_UNICODE_STRING_BUNDLE
{
	UNICODE_STRING	String;
	WCHAR			StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE, * PLDRP_UNICODE_STRING_BUNDLE;
#else
typedef struct _LDRP_UNICODE_STRING_BUNDLE
{
	UNICODE_STRING	String;
	WCHAR			StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE, * PLDRP_UNICODE_STRING_BUNDLE;
#endif

enum class NT_THREAD_INFORMATION_CLASS {

	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger

};

typedef enum class _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute = NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed = NonPagedPool + 2,
	DontUseThisType,
	NonPagedPoolCacheAligned = NonPagedPool + 4,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
	MaxPoolType,
	NonPagedPoolBase = 0,
	NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
	NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
	NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
	NonPagedPoolSession = 32,
	PagedPoolSession = NonPagedPoolSession + 1,
	NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
	DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
	NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
	PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
	NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
	NonPagedPoolNx = 512,
	NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
	NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef enum class _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ULONG GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct {
	ULONG PriorityClass;
	ULONG PrioritySubClass;
} KSPRIORITY, * PKSPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {

	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	LONG					Priority;
	LONG					BasePriority;

} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	_RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	_ACTIVATION_CONTEXT* ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	CHAR* FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	_TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _API_SET_NAMESPACE
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;
	ULONG HashOffset;
	ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;


typedef struct _RTL_BITMAP
{
	ULONG SizeOfBitMap;
	PULONG Buffer;
} RTL_BITMAP, * PRTL_BITMAP;

typedef enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1,
	NtProductLanManNt,
	NtProductServer
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;

typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef struct _SILO_USER_SHARED_DATA
{
	ULONG ServiceSessionId;
	ULONG ActiveConsoleId;
	LONGLONG ConsoleSessionForegroundProcessId;
	NT_PRODUCT_TYPE NtProductType;
	ULONG SuiteMask;
	ULONG SharedUserSessionId; // since RS2
	BOOLEAN IsMultiSessionSku;
	BOOLEAN IsStateSeparationEnabled;
	WCHAR NtSystemRoot[260];
	USHORT UserModeGlobalLogger[16];
	ULONG TimeZoneId; // since 21H2
	LONG TimeZoneBiasStamp;
	KSYSTEM_TIME TimeZoneBias;
	LARGE_INTEGER TimeZoneBiasEffectiveStart;
	LARGE_INTEGER TimeZoneBiasEffectiveEnd;
} SILO_USER_SHARED_DATA, * PSILO_USER_SHARED_DATA;

typedef struct _ACTIVATION_CONTEXT_DATA
{
	ULONG Magic;
	ULONG HeaderSize;
	ULONG FormatVersion;
	ULONG TotalSize;
	ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
	ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
	ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
	ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
	ULONG Flags;
	UNICODE_STRING DosPath;
	HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP
{
	ULONG Flags;
	ULONG AssemblyCount;
	PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
} ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;

typedef struct _TELEMETRY_COVERAGE_HEADER
{
	UCHAR MajorVersion;
	UCHAR MinorVersion;
	struct
	{
		USHORT TracingEnabled : 1;
		USHORT Reserved1 : 15;
	};
	ULONG HashTableEntries;
	ULONG HashIndexMask;
	ULONG TableUpdateVersion;
	ULONG TableSizeInBytes;
	ULONG LastResetTick;
	ULONG ResetRound;
	ULONG Reserved2;
	ULONG RecordedCount;
	ULONG Reserved3[4];
	ULONG HashTable[ANYSIZE_ARRAY];
} TELEMETRY_COVERAGE_HEADER, * PTELEMETRY_COVERAGE_HEADER;

#ifdef _WIN64

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PSLIST_HEADER AtlThunkSListPtr;
	PVOID IFEOKey;

	union __CrossProcessFlags
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1; // REDSTONE5
			ULONG ReservedBits0 : 24;
		};
	}_CrossProcessFlags;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PAPI_SET_NAMESPACE ApiSetMap;
	ULONG TlsExpansionCounter;
	PRTL_BITMAP TlsBitmap;
	ULONG TlsBitmapBits[2]; // TLS_MINIMUM_AVAILABLE

	PVOID ReadOnlySharedMemoryBase;
	PSILO_USER_SHARED_DATA SharedData; // HotpatchInformation
	PVOID* ReadOnlyStaticServerData;

	PVOID AnsiCodePageData; // PCPTABLEINFO
	PVOID OemCodePageData; // PCPTABLEINFO
	PVOID UnicodeCaseTableData; // PNLSTABLEINFO

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	ULARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps; // PHEAP

	PVOID GdiSharedHandleTable; // PGDI_SHARED_MEMORY
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	KAFFINITY ActiveProcessAffinityMask;
	ULONG  GdiHandleBuffer[60];
	PVOID PostProcessInitRoutine;

	PRTL_BITMAP TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32]; // TLS_EXPANSION_SLOTS

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags; // KACF_*
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

	UNICODE_STRING CSDVersion;

	PACTIVATION_CONTEXT_DATA ActivationContextData;
	PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
	PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
	PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
	PVOID PatchLoaderData;
	PVOID ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO

	ULONG AppModelFeatureState;
	ULONG SpareUlongs[2];

	USHORT ActiveCodePage;
	USHORT OemCodePage;
	USHORT UseCaseMapping;
	USHORT UnusedNlsField;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;

	union
	{
		PVOID pContextData; // WIN7
		PVOID pUnused; // WIN10
		PVOID EcCodeBitMap; // WIN11
	};

	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PRTL_CRITICAL_SECTION TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags; // REDSTONE4
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	void* LeapSecondData; // REDSTONE5
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
	ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEB, * PPEB;

typedef struct _TEB
{
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	VOID* SystemReserved1[54];
	LONG ExceptionCode;
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR SpareBytes1[36];
	ULONG TxFsContext;
	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG Win32ClientInfo[62];
	VOID* glDispatchTable[233];
	ULONG glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	VOID* TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	VOID* DbgSsReserved[2];
	ULONG HardErrorMode;
	VOID* Instrumentation[9];
	GUID ActivityId;
	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;
	UCHAR SpareBool0;
	UCHAR SpareBool1;
	UCHAR SpareBool2;
	UCHAR IdealProcessor;
	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG SoftPatchPtr1;
	PVOID ThreadPoolData;
	VOID** TlsExpansionSlots;
	ULONG ImpersonationLocale;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	PVOID CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;
	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	WORD CrossTebFlags;
	ULONG SpareCrossTebBits : 16;
	WORD  SameTebFlags;
	ULONG DbgSafeThunkCall : 1;
	ULONG DbgInDebugPrint : 1;
	ULONG DbgHasFiberData : 1;
	ULONG DbgSkipThreadAttach : 1;
	ULONG DbgWerInShipAssertCode : 1;
	ULONG DbgRanProcessInit : 1;
	ULONG DbgClonedThread : 1;
	ULONG DbgSuppressDebugMsg : 1;
	ULONG SpareSameTebBits : 8;
	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	UINT64 LastSwitchTime;
	UINT64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
} TEB, * PTEB;

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version; // 0 for x64, 1 for x86
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

#else

//0x8 bytes (sizeof)
struct _CLIENT_ID32
{
	ULONG UniqueProcess;                                                    //0x0
	ULONG UniqueThread;                                                     //0x4
};

//0x18 bytes (sizeof)
struct _ACTIVATION_CONTEXT_STACK32
{
	ULONG ActiveFrame;                                                      //0x0
	struct LIST_ENTRY32 FrameListCache;                                     //0x4
	ULONG Flags;                                                            //0xc
	ULONG NextCookieSequenceNumber;                                         //0x10
	ULONG StackId;                                                          //0x14
};

//0x4e0 bytes (sizeof)
struct _GDI_TEB_BATCH32
{
	ULONG Offset : 31;                                                        //0x0
	ULONG HasRenderingCommand : 1;                                            //0x0
	ULONG HDC;                                                              //0x4
	ULONG Buffer[310];                                                      //0x8
};

//0x8 bytes (sizeof)
struct _STRING32
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	ULONG Buffer;                                                           //0x4
};

//0x480 bytes (sizeof)
typedef struct _PEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};
	VOID* Mutant;                                                           //0x4
	VOID* ImageBaseAddress;                                                 //0x8
	struct _PEB_LDR_DATA* Ldr;                                              //0xc
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
	VOID* SubSystemData;                                                    //0x14
	VOID* ProcessHeap;                                                      //0x18
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
	union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x20
	VOID* IFEOKey;                                                          //0x24
	union
	{
		ULONG CrossProcessFlags;                                            //0x28
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x28
			ULONG ProcessInitializing : 1;                                    //0x28
			ULONG ProcessUsingVEH : 1;                                        //0x28
			ULONG ProcessUsingVCH : 1;                                        //0x28
			ULONG ProcessUsingFTH : 1;                                        //0x28
			ULONG ProcessPreviouslyThrottled : 1;                             //0x28
			ULONG ProcessCurrentlyThrottled : 1;                              //0x28
			ULONG ProcessImagesHotPatched : 1;                                //0x28
			ULONG ReservedBits0 : 24;                                         //0x28
		};
	};
	union
	{
		VOID* KernelCallbackTable;                                          //0x2c
		VOID* UserSharedInfoPtr;                                            //0x2c
	};
	ULONG SystemReserved;                                                   //0x30
	union _SLIST_HEADER* volatile AtlThunkSListPtr32;                       //0x34
	VOID* ApiSetMap;                                                        //0x38
	ULONG TlsExpansionCounter;                                              //0x3c
	VOID* TlsBitmap;                                                        //0x40
	ULONG TlsBitmapBits[2];                                                 //0x44
	VOID* ReadOnlySharedMemoryBase;                                         //0x4c
	VOID* SharedData;                                                       //0x50
	VOID** ReadOnlyStaticServerData;                                        //0x54
	VOID* AnsiCodePageData;                                                 //0x58
	VOID* OemCodePageData;                                                  //0x5c
	VOID* UnicodeCaseTableData;                                             //0x60
	ULONG NumberOfProcessors;                                               //0x64
	ULONG NtGlobalFlag;                                                     //0x68
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
	ULONG HeapSegmentReserve;                                               //0x78
	ULONG HeapSegmentCommit;                                                //0x7c
	ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
	ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
	ULONG NumberOfHeaps;                                                    //0x88
	ULONG MaximumNumberOfHeaps;                                             //0x8c
	VOID** ProcessHeaps;                                                    //0x90
	VOID* GdiSharedHandleTable;                                             //0x94
	VOID* ProcessStarterHelper;                                             //0x98
	ULONG GdiDCAttributeList;                                               //0x9c
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
	ULONG OSMajorVersion;                                                   //0xa4
	ULONG OSMinorVersion;                                                   //0xa8
	USHORT OSBuildNumber;                                                   //0xac
	USHORT OSCSDVersion;                                                    //0xae
	ULONG OSPlatformId;                                                     //0xb0
	ULONG ImageSubsystem;                                                   //0xb4
	ULONG ImageSubsystemMajorVersion;                                       //0xb8
	ULONG ImageSubsystemMinorVersion;                                       //0xbc
	ULONG ActiveProcessAffinityMask;                                        //0xc0
	ULONG GdiHandleBuffer[34];                                              //0xc4
	VOID(*PostProcessInitRoutine)();                                       //0x14c
	VOID* TlsExpansionBitmap;                                               //0x150
	ULONG TlsExpansionBitmapBits[32];                                       //0x154
	ULONG SessionId;                                                        //0x1d4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
	VOID* pShimData;                                                        //0x1e8
	VOID* AppCompatInfo;                                                    //0x1ec
	struct _UNICODE_STRING CSDVersion;                                      //0x1f0
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x1f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x1fc
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x200
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x204
	ULONG MinimumStackCommit;                                               //0x208
	VOID* SparePointers[4];                                                 //0x20c
	ULONG SpareUlongs[5];                                                   //0x21c
	VOID* WerRegistrationData;                                              //0x230
	VOID* WerShipAssertPtr;                                                 //0x234
	VOID* pUnused;                                                          //0x238
	VOID* pImageHeaderHash;                                                 //0x23c
	union
	{
		ULONG TracingFlags;                                                 //0x240
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x240
			ULONG CritSecTracingEnabled : 1;                                  //0x240
			ULONG LibLoaderTracingEnabled : 1;                                //0x240
			ULONG SpareTracingBits : 29;                                      //0x240
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
	ULONG TppWorkerpListLock;                                               //0x250
	struct _LIST_ENTRY TppWorkerpList;                                      //0x254
	VOID* WaitOnAddressHashTable[128];                                      //0x25c
	VOID* TelemetryCoverageHeader;                                          //0x45c
	ULONG CloudFileFlags;                                                   //0x460
	ULONG CloudFileDiagFlags;                                               //0x464
	CHAR PlaceholderCompatibilityMode;                                      //0x468
	CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
	struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x470
	union
	{
		ULONG LeapSecondFlags;                                              //0x474
		struct
		{
			ULONG SixtySecondEnabled : 1;                                     //0x474
			ULONG Reserved : 31;                                              //0x474
		};
	};
	ULONG NtGlobalFlag2;                                                    //0x478
} PEB, * PPEB;

//0x1018 bytes (sizeof)
typedef struct _TEB
{
	struct _NT_TIB32 NtTib;                                                 //0x0
	ULONG EnvironmentPointer;                                               //0x1c
	struct _CLIENT_ID32 ClientId;                                           //0x20
	ULONG ActiveRpcHandle;                                                  //0x28
	ULONG ThreadLocalStoragePointer;                                        //0x2c
	ULONG ProcessEnvironmentBlock;                                          //0x30
	ULONG LastErrorValue;                                                   //0x34
	ULONG CountOfOwnedCriticalSections;                                     //0x38
	ULONG CsrClientThread;                                                  //0x3c
	ULONG Win32ThreadInfo;                                                  //0x40
	ULONG User32Reserved[26];                                               //0x44
	ULONG UserReserved[5];                                                  //0xac
	ULONG WOW32Reserved;                                                    //0xc0
	ULONG CurrentLocale;                                                    //0xc4
	ULONG FpSoftwareStatusRegister;                                         //0xc8
	ULONG ReservedForDebuggerInstrumentation[16];                           //0xcc
	ULONG SystemReserved1[26];                                              //0x10c
	CHAR PlaceholderCompatibilityMode;                                      //0x174
	UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x175
	CHAR PlaceholderReserved[10];                                           //0x176
	ULONG ProxiedProcessId;                                                 //0x180
	struct _ACTIVATION_CONTEXT_STACK32 _ActivationStack;                    //0x184
	UCHAR WorkingOnBehalfTicket[8];                                         //0x19c
	LONG ExceptionCode;                                                     //0x1a4
	ULONG ActivationContextStackPointer;                                    //0x1a8
	ULONG InstrumentationCallbackSp;                                        //0x1ac
	ULONG InstrumentationCallbackPreviousPc;                                //0x1b0
	ULONG InstrumentationCallbackPreviousSp;                                //0x1b4
	UCHAR InstrumentationCallbackDisabled;                                  //0x1b8
	UCHAR SpareBytes[23];                                                   //0x1b9
	ULONG TxFsContext;                                                      //0x1d0
	struct _GDI_TEB_BATCH32 GdiTebBatch;                                    //0x1d4
	struct _CLIENT_ID32 RealClientId;                                       //0x6b4
	ULONG GdiCachedProcessHandle;                                           //0x6bc
	ULONG GdiClientPID;                                                     //0x6c0
	ULONG GdiClientTID;                                                     //0x6c4
	ULONG GdiThreadLocalInfo;                                               //0x6c8
	ULONG Win32ClientInfo[62];                                              //0x6cc
	ULONG glDispatchTable[233];                                             //0x7c4
	ULONG glReserved1[29];                                                  //0xb68
	ULONG glReserved2;                                                      //0xbdc
	ULONG glSectionInfo;                                                    //0xbe0
	ULONG glSection;                                                        //0xbe4
	ULONG glTable;                                                          //0xbe8
	ULONG glCurrentRC;                                                      //0xbec
	ULONG glContext;                                                        //0xbf0
	ULONG LastStatusValue;                                                  //0xbf4
	struct _STRING32 StaticUnicodeString;                                   //0xbf8
	WCHAR StaticUnicodeBuffer[261];                                         //0xc00
	ULONG DeallocationStack;                                                //0xe0c
	ULONG TlsSlots[64];                                                     //0xe10
	struct LIST_ENTRY32 TlsLinks;                                           //0xf10
	ULONG Vdm;                                                              //0xf18
	ULONG ReservedForNtRpc;                                                 //0xf1c
	ULONG DbgSsReserved[2];                                                 //0xf20
	ULONG HardErrorMode;                                                    //0xf28
	ULONG Instrumentation[9];                                               //0xf2c
	struct _GUID ActivityId;                                                //0xf50
	ULONG SubProcessTag;                                                    //0xf60
	ULONG PerflibData;                                                      //0xf64
	ULONG EtwTraceData;                                                     //0xf68
	ULONG WinSockData;                                                      //0xf6c
	ULONG GdiBatchCount;                                                    //0xf70
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0xf74
		ULONG IdealProcessorValue;                                          //0xf74
		struct
		{
			UCHAR ReservedPad0;                                             //0xf74
			UCHAR ReservedPad1;                                             //0xf75
			UCHAR ReservedPad2;                                             //0xf76
			UCHAR IdealProcessor;                                           //0xf77
		};
	};
	ULONG GuaranteedStackBytes;                                             //0xf78
	ULONG ReservedForPerf;                                                  //0xf7c
	ULONG ReservedForOle;                                                   //0xf80
	ULONG WaitingOnLoaderLock;                                              //0xf84
	ULONG SavedPriorityState;                                               //0xf88
	ULONG ReservedForCodeCoverage;                                          //0xf8c
	ULONG ThreadPoolData;                                                   //0xf90
	ULONG TlsExpansionSlots;                                                //0xf94
	ULONG MuiGeneration;                                                    //0xf98
	ULONG IsImpersonating;                                                  //0xf9c
	ULONG NlsCache;                                                         //0xfa0
	ULONG pShimData;                                                        //0xfa4
	ULONG HeapData;                                                         //0xfa8
	ULONG CurrentTransactionHandle;                                         //0xfac
	ULONG ActiveFrame;                                                      //0xfb0
	ULONG FlsData;                                                          //0xfb4
	ULONG PreferredLanguages;                                               //0xfb8
	ULONG UserPrefLanguages;                                                //0xfbc
	ULONG MergedPrefLanguages;                                              //0xfc0
	ULONG MuiImpersonation;                                                 //0xfc4
	union
	{
		volatile USHORT CrossTebFlags;                                      //0xfc8
		USHORT SpareCrossTebBits : 16;                                        //0xfc8
	};
	union
	{
		USHORT SameTebFlags;                                                //0xfca
		struct
		{
			USHORT SafeThunkCall : 1;                                         //0xfca
			USHORT InDebugPrint : 1;                                          //0xfca
			USHORT HasFiberData : 1;                                          //0xfca
			USHORT SkipThreadAttach : 1;                                      //0xfca
			USHORT WerInShipAssertCode : 1;                                   //0xfca
			USHORT RanProcessInit : 1;                                        //0xfca
			USHORT ClonedThread : 1;                                          //0xfca
			USHORT SuppressDebugMsg : 1;                                      //0xfca
			USHORT DisableUserStackWalk : 1;                                  //0xfca
			USHORT RtlExceptionAttached : 1;                                  //0xfca
			USHORT InitialThread : 1;                                         //0xfca
			USHORT SessionAware : 1;                                          //0xfca
			USHORT LoadOwner : 1;                                             //0xfca
			USHORT LoaderWorker : 1;                                          //0xfca
			USHORT SkipLoaderInit : 1;                                        //0xfca
			USHORT SkipFileAPIBrokering : 1;                                  //0xfca
		};
	};
	ULONG TxnScopeEnterCallback;                                            //0xfcc
	ULONG TxnScopeExitCallback;                                             //0xfd0
	ULONG TxnScopeContext;                                                  //0xfd4
	ULONG LockCount;                                                        //0xfd8
	LONG WowTebOffset;                                                      //0xfdc
	ULONG ResourceRetValue;                                                 //0xfe0
	ULONG ReservedForWdf;                                                   //0xfe4
	ULONGLONG ReservedForCrt;                                               //0xfe8
	struct _GUID EffectiveContainerId;                                      //0xff0
	ULONGLONG LastSleepCounter;                                             //0x1000
	ULONG SpinCallCount;                                                    //0x1008
	ULONGLONG ExtendedFeatureDisableMask;                                   //0x1010
} TEB, * PTEB;

#endif

typedef enum class _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	LONG					Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	KWAIT_REASON            WaitReason;
} SYSTEM_THREAD, * PSYSTEM_THREAD;

enum class KTHREAD_STATE : ULONG
{
	Initialized,
	Ready,
	Running,
	Standby,
	Terminated,
	Waiting,
	Transition,
	DeferredReady,
	GateWaitObsolete,
	WaitingForProcessInSwap
};

typedef struct _VM_COUNTERS {
	SIZE_T		   PeakVirtualSize;
	SIZE_T         PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
	SIZE_T         VirtualSize;
} VM_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG			NextEntryOffset;
	ULONG			NumberOfThreads;
	LARGE_INTEGER	WorkingSetPrivateSize;
	ULONG			HardFaultCount;
	ULONG			NumberOfThreadsHighWatermark;
	ULONGLONG		CycleTime;
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ImageName;
	LONG			BasePriority;
	HANDLE			UniqueProcessId;
	HANDLE			InheritedFromUniqueProcessId;
	ULONG			HandleCount;
	ULONG			SessionId;
	ULONG_PTR		UniqueProcessKey;
	SIZE_T			PeakVirtualSize;
	SIZE_T			VirtualSize;
	ULONG			PageFaultCount;
	SIZE_T 			PeakWorkingSetSize;
	SIZE_T			WorkingSetSize;
	SIZE_T			QuotaPeakPagedPoolUsage;
	SIZE_T 			QuotaPagedPoolUsage;
	SIZE_T 			QuotaPeakNonPagedPoolUsage;
	SIZE_T 			QuotaNonPagedPoolUsage;
	SIZE_T 			PagefileUsage;
	SIZE_T 			PeakPagefileUsage;
	SIZE_T 			PrivatePageCount;
	LARGE_INTEGER	ReadOperationCount;
	LARGE_INTEGER	WriteOperationCount;
	LARGE_INTEGER	OtherOperationCount;
	LARGE_INTEGER 	ReadTransferCount;
	LARGE_INTEGER	WriteTransferCount;
	LARGE_INTEGER	OtherTransferCount;
	SYSTEM_THREAD	Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum class _PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
	ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
	ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
	ProcessHandleTable, // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
	ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
	ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
	ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
	ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
	ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
	ProcessImageSection, // q: HANDLE
	ProcessDebugAuthInformation, // since REDSTONE4 // 90
	ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber, // q: ULONGLONG
	ProcessLoaderDetour, // since REDSTONE5
	ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
	ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
	ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
	ProcessCreateStateChange, // since WIN11
	ProcessApplyStateChange,
	ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
	ProcessAltPrefetchParam, // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
	ProcessAssignCpuPartitions,
	ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
	ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
	ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT // 110
	ProcessEffectivePagePriority, // q: ULONG
	ProcessSchedulerSharedData, // since 24H2
	ProcessSlistRollbackInformation,
	ProcessNetworkIoCounters, // q: PROCESS_NETWORK_COUNTERS
	ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	KAFFINITY AffinityMask;
	LONG   BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

//------------------------------------------------------------------------------------------------------
#pragma endregion STRUCTS

#pragma region FUNCTIONS
//------------------------------------------------------------------------------------------------------
//https://ntdoc.m417z.com/ntcreatethreadex
typedef
NTSTATUS (NTAPI * NtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, 
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef 
NTSTATUS
(NTAPI* NtQueryObject)(
	IN HANDLE               ObjectHandle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID               ObjectInformation,
	IN ULONG                Length,
	OUT PULONG              ResultLength);

#ifdef _WIN64
typedef
NTSTATUS(__fastcall* LdrpLoadDll)
(
    UNICODE_STRING* dll_path,
    LDRP_PATH_SEARCH_CONTEXT* search_path,
    LDRP_LOAD_CONTEXT_FLAGS	Flags,
	_LDR_DATA_TABLE_ENTRY** DllEntry
);

typedef NTSTATUS(NTAPI* LdrLoadDll)(PWCHAR DllPath, ULONG Flags, UNICODE_STRING* DllName, PHANDLE BaseAddress);
typedef NTSTATUS(NTAPI* RtlInitUnicodeString)(UNICODE_STRING*, PCWSTR);
typedef BOOL (WINAPI* Basep8BitStringToDynamicUnicodeString)(PUNICODE_STRING pConvertedStr, LPCSTR pszAnsiStr);

#else
typedef
NTSTATUS(__fastcall* LdrpLoadDll)
(
	UNICODE_STRING_32* dll_path,
	LDRP_PATH_SEARCH_CONTEXT_32* search_path,
	LDRP_LOAD_CONTEXT_FLAGS_32 Flags,
	_LDR_DATA_TABLE_ENTRY_32** DllEntry
);

typedef NTSTATUS(NTAPI* LdrLoadDll)(PWCHAR DllPath, ULONG Flags, UNICODE_STRING_32* DllName, PHANDLE BaseAddress);
typedef NTSTATUS(NTAPI* RtlInitUnicodeString)(UNICODE_STRING_32*, PCWSTR);

#endif

#ifdef _WIN64
typedef
void (__fastcall* LdrpLoadDllInternal)
(
	UNICODE_STRING* FullPath,
	LDRP_PATH_SEARCH_CONTEXT* search_path,
	LDRP_LOAD_CONTEXT_FLAGS Flags,
	ULONG32	LdrFlags,
	LDR_DATA_TABLE_ENTRY* LdrEntry,
	LDR_DATA_TABLE_ENTRY* LdrEntry2,
	LDR_DATA_TABLE_ENTRY** DllEntry,
	_Out_ NTSTATUS* pStatus,
	ULONG Zero 
);


/*
 *v9 = LdrpPreprocessDllName(dll_path, &v10, 0i64, &v8);
  if ( (v9 & 0x80000000) == 0 )
	LdrpLoadDllInternal((__int64)&v10, (int)search_path, v8, 4, 0i64, 0i64, (__int64 *)a4, (int *)&v9, 0i64);
 */
typedef
NTSTATUS(__fastcall* LdrpPreprocessDllName)
(
	UNICODE_STRING* DllName,
	LDRP_UNICODE_STRING_BUNDLE* OutputDllName, // LDRP_UNICODE_STRING_BUNDLE* OutputDllName,
	LDR_DATA_TABLE_ENTRY* pOptParentEntry,
	LDRP_LOAD_CONTEXT_FLAGS* LoadContextFlags
);

typedef NTSTATUS(*NtQueryInformationThread)(
	HANDLE          ThreadHandle,
	NT_THREAD_INFORMATION_CLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
	);

typedef NTSTATUS (*NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef NTSTATUS (*NtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

typedef NTSTATUS(*RtlAdjustPrivilege)

(
	ULONG    Privilege,
	BOOLEAN  Enable,
	BOOLEAN  CurrentThread,
	PBOOLEAN Enabled
);

typedef void(__stdcall* LdrProtectMrdata)(BOOL a);

typedef NTSTATUS (NTAPI* NtSetInformationProcess)(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_In_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength
	);

#else

typedef
void(__fastcall* LdrpLoadDllInternal)
(
	UNICODE_STRING* FullPath,
	LDRP_PATH_SEARCH_CONTEXT_32* search_path,
	LDRP_LOAD_CONTEXT_FLAGS_32 Flags,
	ULONG32	LdrFlags, // = 4
	LDR_DATA_TABLE_ENTRY_32* LdrEntry,
	LDR_DATA_TABLE_ENTRY_32* LdrEntry2,
	LDR_DATA_TABLE_ENTRY_32** DllEntry,
	_Out_ NTSTATUS* pStatus,
	ULONG Zero 
);

typedef
NTSTATUS(__fastcall* LdrpPreprocessDllName)
(
	UNICODE_STRING_32* DllName,
	LDRP_UNICODE_STRING_BUNDLE* OutputDllName, // LDRP_UNICODE_STRING_BUNDLE* OutputDllName,
	LDR_DATA_TABLE_ENTRY_32* pOptParentEntry,
	LDRP_LOAD_CONTEXT_FLAGS_32* LoadContextFlags
	);

typedef NTSTATUS(__stdcall*NtQueryInformationThread)(
	HANDLE          ThreadHandle,
	NT_THREAD_INFORMATION_CLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
	);

typedef NTSTATUS(__stdcall*NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(__stdcall*NtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef NTSTATUS(__stdcall*RtlAdjustPrivilege)

(
	ULONG    Privilege,
	BOOLEAN  Enable,
	BOOLEAN  CurrentThread,
	PBOOLEAN Enabled
	);

typedef void(__stdcall* LdrProtectMrdata)(BOOL a);

#endif

//------------------------------------------------------------------------------------------------------
#pragma endregion FUNCTIONS