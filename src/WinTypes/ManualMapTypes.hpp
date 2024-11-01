#pragma once

typedef struct _TLS_ENTRY
{
    LIST_ENTRY				TlsEntryLinks;
    IMAGE_TLS_DIRECTORY		TlsDirectory;
    PVOID 					ModuleEntry; //LdrDataTableEntry
    SIZE_T					TlsIndex;
} TLS_ENTRY, * PTLS_ENTRY;

typedef DWORD64(__fastcall* LdrpHandleTlsData)(PLDR_DATA_TABLE_ENTRY);
typedef void(__stdcall* _RtlZeroMemory)(PVOID, SIZE_T);