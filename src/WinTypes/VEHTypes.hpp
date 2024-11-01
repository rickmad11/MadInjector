#pragma once

namespace Dump
{
    typedef struct _RTL_SRWLOCK
    {
        union
        {
            struct
            {
                unsigned __int64 Locked : 1;
                unsigned __int64 Waiting : 1;
                unsigned __int64 Waking : 1;
                unsigned __int64 MultipleShared : 1;
                unsigned __int64 Shared : 60;
            };
            unsigned __int64 Value;
            void* Ptr;
        };
    } RTL_SRWLOCK, * PRTL_SRWLOCK;
}

typedef struct _VECTORED_HANDLER_ENTRY
{
    _VECTORED_HANDLER_ENTRY* Flink;                //0x0
    _VECTORED_HANDLER_ENTRY* Blink;                //0x8
    PVOID pDword;                                  //0x10 points to 1 usually
    int64_t pUnknown2;                             //0x18 usually 0 when VEH is registered otherwise valid pointer to itself in list, I only encountered 1-2 process having trash values in here
    PVECTORED_EXCEPTION_HANDLER pfVectoredHandler; //0x20 Encoded Function Pointer of type PVECTORED_EXCEPTION_HANDLER
} VECTORED_HANDLER_ENTRY, * PVECTORED_HANDLER_ENTRY;

typedef struct _LDRP_VECTOR_HANDLER_LIST {
    Dump::RTL_SRWLOCK LdrpVehLock;
    PVECTORED_HANDLER_ENTRY FLdrpVehList;
    PVECTORED_HANDLER_ENTRY BLdrpVehList;
    Dump::RTL_SRWLOCK LdrpVchLock;
    PVECTORED_HANDLER_ENTRY FLdrpVchList;
    PVECTORED_HANDLER_ENTRY BLdrpVchList;
} LDRP_VECTOR_HANDLER_LIST, * PLDRP_VECTOR_HANDLER_LIST;
