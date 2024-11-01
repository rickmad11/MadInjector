#pragma once

#ifdef _WIN64

#include "WinTypes/ManualMapTypes.hpp"

namespace oManualMapper {

	struct MANUAL_MAP_BUFFER
	{
		decltype(VirtualProtect)* pfVirtualProtect = nullptr;
		decltype(RtlAddFunctionTable)* pfRtlAddFunctionTable = nullptr;
		LdrpHandleTlsData pfLdrpHandleTlsData = nullptr;
		void* (__stdcall* pfLoadLibraryAEx)(const char* dll_name, MANUAL_MAP_BUFFER* buffer) = nullptr;
		LdrpLoadDll pfLdrpLoadDll = nullptr;
		Basep8BitStringToDynamicUnicodeString pfBasep8BitStringToDynamicUnicodeString = nullptr;
		void* allocated_dll = nullptr;
		void* (__stdcall* pfGetProcAddress)(void* dll_base, std::uintptr_t function, MANUAL_MAP_BUFFER* buffer) = nullptr;
		void(__stdcall* pfApplyModuleModifications)(MANUAL_MAP_BUFFER* buffer) = nullptr;
		decltype(MultiByteToWideChar)* pfMultiByteToWideChar = nullptr;
		_RtlZeroMemory pfRtlZeroMemory = nullptr;
		PLIST_ENTRY pLdrpTlsList = nullptr;
		DWORD64 flags = 0;
		LONG e_lfanew = 0;

		bool execution_finished = false;
		bool needs_reloc_fix = false;
		bool exception_failed = false;

		UNICODE_STRING module_name{};
		LDRP_PATH_SEARCH_CONTEXT path_sc{};
		LDRP_LOAD_CONTEXT_FLAGS lc_flags{};
		PLDR_DATA_TABLE_ENTRY ldr_entry{};
	};

}

#endif //_WIN64