#pragma once

//LoadLibrary -> LoadLibrary.cpp
bool MI_wLoadLibrary(const wchar_t* dllpath, DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64);

//LdrLoadDLL -> LdrLoadDLL.cpp
bool MI_wLdrLoadDll(const wchar_t* dllpath, DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64);

//LdrpLoadDll -> LdrpLoadDll.cpp
bool MI_wLdrpLoadDll(const wchar_t* dllpath, DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64);

//LdrpLoadDllInternal -> LdrpLoadDllInternal.cpp
bool MI_wLdrpLoadDllInternal(const wchar_t* dllpath, DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64);

bool HandleHijacker(DWORD target_pid, DWORD desired_handle_access_flags, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64, void* pfInject, enum class Injection_Method injection_method, const wchar_t* dllpath_to_inject);

namespace oManualMapper { bool ManualMapperStub(const wchar_t* dllpath, DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64); }

bool UnlinkModule(const wchar_t* dllpath, DWORD pid, void*, void*, DWORD64 additional_flags, bool is_x64);

bool UnloadMappedDll(void*, DWORD pid, void*, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64);

#define INSIDE_HIJACKED_HANDLE_PROCESS	(DWORD64)(1ULL << 6)

namespace HandleHijackerGlobal
{
	struct HandleHijackerAdditionalArgs
	{
		const wchar_t* path = nullptr;
		HANDLE hijacked_handle = nullptr;
	}inline AdditionalArgs;
}
