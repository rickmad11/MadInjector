#include "pch.h"

#ifdef _WIN64

#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "GenericShellcode.hpp"

namespace oThreadPool
{
	bool Injection(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
		constexpr DWORD access_flags = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
		HANDLE process_handle = nullptr;

		if (additional_flags & MI_HIJACK_HANDLE)
			return HandleHijacker(pid, access_flags, exec_method, additional_flags, is_x64, Injection, injection_method, dllpath);

		const bool is_inside_hijacked_process = additional_flags & INSIDE_HIJACKED_HANDLE_PROCESS;
		if (is_inside_hijacked_process)
		{
			Utility::LoadSymbols(HandleHijackerGlobal::AdditionalArgs.path);
			process_handle = HandleHijackerGlobal::AdditionalArgs.hijacked_handle;
		}
		else
			process_handle = OpenProcess(access_flags, NULL, pid);

		if (!process_handle)
		{
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		DWORD allocation_flags = MEM_COMMIT | MEM_RESERVE;
		void* const allocated_memory_thread_data = VirtualAllocEx(process_handle, nullptr, sizeof(THREAD_BUFFER), allocation_flags, PAGE_READWRITE);

		if (!allocated_memory_thread_data)
		{
			CONSOLE_LOG_ERROR("failed allocating thread data")
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		THREAD_BUFFER buffer;

		HMODULE kernel_module = GetModuleHandleW(L"Kernel32.dll");
		HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");

		buffer.pfRtlInitUnicodeString		= reinterpret_cast<RtlInitUnicodeString>(GetProcAddress(ntdll_module, "RtlInitUnicodeString"));
		buffer.pfLoadLibrary				= reinterpret_cast<decltype(LoadLibraryW)*>(GetProcAddress(kernel_module, "LoadLibraryW"));
		buffer.pfLdrLoadDll					= reinterpret_cast<LdrLoadDll>(GetProcAddress(ntdll_module, "LdrLoadDll"));
		buffer.pfLdrpLoadDll				= SymbolParser::FindFunction<LdrpLoadDll>("LdrpLoadDll");
		buffer.pfLdrpLoadDllInternal		= SymbolParser::FindFunction<LdrpLoadDllInternal>("LdrpLoadDllInternal");
		buffer.pfLdrpPreprocessDllName		= SymbolParser::FindFunction<LdrpPreprocessDllName>("LdrpPreprocessDllName");

		buffer.injection_method				= injection_method;
		buffer.injection_status				= false;

		buffer.additional_flags				= additional_flags;

		memcpy_s(buffer.dllpath, sizeof(buffer.dllpath), dllpath, (std::wcslen(dllpath) * sizeof(wchar_t)) + 2);

		if (!WriteProcessMemory(process_handle, allocated_memory_thread_data, &buffer, sizeof(THREAD_BUFFER), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "writing buffer failed", allocated_memory_thread_data);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		ULONG_PTR size_function = reinterpret_cast<ULONG_PTR>(Dummy) - reinterpret_cast<ULONG_PTR>(Shellcode);

		void* const allocated_memory_code = VirtualAllocEx(process_handle, nullptr, size_function, allocation_flags, PAGE_EXECUTE_READ);

		if (!allocated_memory_code)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "allocating function failed", allocated_memory_thread_data);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_memory_code, Shellcode, size_function, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing Shellcode failed", allocated_memory_thread_data, allocated_memory_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		const bool status = Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, additional_flags, pid);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data, allocated_memory_code);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return status;
	}
}

#endif