#pragma once

//Entry
MI_API
bool wMadInjector(const wchar_t* dllpath, DWORD pid, DWORD64 injection_flag, DWORD64 execution_flag, DWORD64 additional_flags, bool is_x64 = true);

MI_API
bool MadInjector(const char* dllpath, DWORD pid, DWORD64 injection_flag, DWORD64 execution_flag, DWORD64 additional_flags, bool is_x64);

//injection flag only one can be set at the same time
#define MI_LOAD_LIBRARY				  (DWORD64)1ULL
#define MI_LDR_LOAD_DLL				  (DWORD64)(1ULL << 1)
#define MI_LDR_P_LOAD_DLL			  (DWORD64)(1ULL << 2)
#define MI_LDR_P_LOAD_DLL_INTERNAL	  (DWORD64)(1ULL << 3)
#define MI_MANUAL_MAP				  (DWORD64)(1ULL << 4)

//execution flag only one can be set at the same time
#define MI_CREATE_REMOTE_THREAD		  (DWORD64)1ULL
#define MI_NT_CREATE_THREAD_EX		  (DWORD64)(1ULL << 1)
#define MI_SET_WINDOWS_HOOK			  (DWORD64)(1ULL << 2)
#define MI_THREAD_HIJACK			  (DWORD64)(1ULL << 3)
#define MI_QUEUE_USER_APC 			  (DWORD64)(1ULL << 4)
#define MI_KERNEL_CALLBACK_TABLE 	  (DWORD64)(1ULL << 5)
#define MI_VECTORED_EXCEPTION_HANDLER (DWORD64)(1ULL << 7)

//additional flags use bitwise or to enable them. Only pick one console flag
#define MI_CREATE_NEW_CONSOLE		  (DWORD64)1ULL 
#define MI_USE_EXISTING_CONSOLE		  (DWORD64)(1ULL << 1)

//additional flags use bitwise or to enable them. These are for MI_NT_CREATE_THREAD_EX you can use all of them at once depending on what you want
#define MI_THREAD_HIDE_FROM_DEBUGGER  (DWORD64)(1ULL << 2)
#define MI_THREAD_SKIP_THREAD_ATTACH  (DWORD64)(1ULL << 3)
#define MI_THREAD_START_ADDRESS_SPOOF (DWORD64)(1ULL << 4)

//additional flags use bitwise or to enable them. These are for the Handle Hijacker 
#define MI_HIJACK_HANDLE			  (DWORD64)(1ULL << 5)
#define MI_SYSTEM_PROCESS_ONLY        (DWORD64)(1ULL << 12)

//additional flags use bitwise or to enable them. These are for the Manual Mapper
#define MI_EXCEPTION_SUPPORT		  (DWORD64)(1ULL << 7)
#define MI_SECURITY_COOKIE		      (DWORD64)(1ULL << 8)
#define MI_BOUND_IMPORTS		      (DWORD64)(1ULL << 9)
#define MI_DELAY_IMPORTS		      (DWORD64)(1ULL << 10)
#define MI_TLS						  (DWORD64)(1ULL << 11)
#define MI_MODIFY_MODULE	          (DWORD64)(1ULL << 14)
#define MI_REMOVE_BOUND_IMPORTS	      (DWORD64)(1ULL << 15)
#define MI_REMOVE_IMPORTS	          (DWORD64)(1ULL << 16)
#define MI_REMOVE_RELOCATIONS	      (DWORD64)(1ULL << 17)
#define MI_REMOVE_RESOURCES	          (DWORD64)(1ULL << 18)
#define MI_REMOVE_EXPORT_TABLE	      (DWORD64)(1ULL << 19)
#define MI_REMOVE_TLS				  (DWORD64)(1ULL << 20)
#define MI_REMOVE_DEBUG_DATA		  (DWORD64)(1ULL << 21)
#define MI_REMOVE_PE_HEADER			  (DWORD64)(1ULL << 22)
#define MI_REMOVE_DOS_HEADER		  (DWORD64)(1ULL << 23)
#define MI_REMOVE_RICH_HEADER		  (DWORD64)(1ULL << 24)
#define MI_REMOVE_DOS_STUB			  (DWORD64)(1ULL << 25)
#define MI_SECTION_REMOVE_RELOC		  (DWORD64)(1ULL << 27)
#define MI_SECTION_REMOVE_RSRC		  (DWORD64)(1ULL << 28)
#define MI_SECTION_REMOVE_PDATA		  (DWORD64)(1ULL << 29)

//additional flags use bitwise or to enable them. This one is just for the single function which unlinks module from peb
#define MI_UNLINK_MODULE			  (DWORD64)(1ULL << 13)
#define MI_UNLOAD_MAPPED_MODULE		  (DWORD64)(1ULL << 26)
#define MI_UNLINK_MODULE_INTERNAL     (DWORD64)(1ULL << 40)

//additional flags use bitwise or to enable them. These are for the Thread Pool Execution
#define MI_THREAD_POOL_EXECUTION	  (DWORD64)(1ULL << 30)
#define MI_WORKER_THREAD_CREATION	  (DWORD64)(1ULL << 31)
#define MI_POOL_TP_WORK_INSERTION	  (DWORD64)(1ULL << 32)
#define MI_POOL_TP_JOB_INSERTION	  (DWORD64)(1ULL << 33)
#define MI_POOL_TP_DIRECT			  (DWORD64)(1ULL << 34)
#define MI_POOL_TP_WAIT				  (DWORD64)(1ULL << 35)
#define MI_POOL_TP_TIMER			  (DWORD64)(1ULL << 36)
#define MI_POOL_TP_IO				  (DWORD64)(1ULL << 37)
#define MI_POOL_TP_ALPC				  (DWORD64)(1ULL << 38)

//additional flags use bitwise or to enable them. Instrumentation Callback execution flags
#define MI_INSTRUMENTATION_CALLBACK   (DWORD64)(1ULL << 39)

//additional flags use bitwise or to enable them. Tls Callback execution flags
#define MI_TLS_CALLBACK_EXECUTION     (DWORD64)(1ULL << 41)

//flag (DWORD64)(1ULL << 6) is reserved for internal usage

/*
 Supported exec_methods
 - L"CreateRemoteThread"
 - L"NtCreateThreadEx"
 - L"SetWindowsHook"
 - L"ThreadHijack"
 - L"QueueUserAPC"
 - L"KernelCallbackTable"
 - L"VectoredExceptionHandler"
 - L"ThreadPool"
 - L"InstrumentationCallback"

 Supported injection_methods
 - L"LoadLibrary",
 - L"LdrLoadDll",
 - L"LdrpLoadDll",
 - L"LdrpLoadDllInternal",
 - L"ManualMap",
 */

/*
	Additional infos to MI_CREATE_NEW_CONSOLE

	A process can be attached to at most one console. If the calling process is already attached to a console, the error code returned is ERROR_ACCESS_DENIED.

	Call this function before calling MadInjector if you want a console,
	if you use this make sure your application does not use one simply call FreeConsole on your app in order to solve this
 */

/*
	Additional infos to MI_USE_EXISTING_CONSOLE

	use this if you dont want to make a new one instead write to your console (you need to have a console tho lol)
 */