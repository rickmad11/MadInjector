#include "pch.h"

#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "SymbolParser/SymbolParser.h"
#include "GenericShellcode.hpp"

namespace oCreateThread
{
	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, const wchar_t* const exec_method, DWORD64 additional_flags)
	{
		if (!wcscmp(exec_method, L"NtCreateThreadEx"))
		{
			HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
			NtCreateThreadEx pNtCreateThreadEx = reinterpret_cast<NtCreateThreadEx>(GetProcAddress(ntdll, "NtCreateThreadEx"));

			ULONG thread_creation_flags{ NULL };

			if (additional_flags & MI_THREAD_HIDE_FROM_DEBUGGER)
				thread_creation_flags = THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
			if (additional_flags & MI_THREAD_SKIP_THREAD_ATTACH)
				thread_creation_flags |= THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH; // might lead to issues
			if (additional_flags & MI_THREAD_START_ADDRESS_SPOOF)
				thread_creation_flags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

			HANDLE thread_handle = nullptr;

			PUSER_THREAD_START_ROUTINE thread_start_address = nullptr;

			if (additional_flags & MI_THREAD_START_ADDRESS_SPOOF)
				thread_start_address = reinterpret_cast<PUSER_THREAD_START_ROUTINE>(0);
			else
				thread_start_address = reinterpret_cast<PUSER_THREAD_START_ROUTINE>(allocated_memory_code);

			NTSTATUS status = pNtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS,
				nullptr, process_handle,
				thread_start_address, allocated_memory_thread_data,
				thread_creation_flags, NULL,
				NULL, NULL,
				nullptr);

			if (status != 0)
				return false;

			if (additional_flags & MI_THREAD_START_ADDRESS_SPOOF)
			{
				CONTEXT thread_context{};
				thread_context.ContextFlags = CONTEXT_ALL;

				if (!GetThreadContext(thread_handle, &thread_context))
					return false;

#ifdef _WIN64
				//2 way to find out where the thread_start_address is stored 1st and my favorite solution is GOOGLE.
				//The second one is looking at NtCreateThreadEx in ntoskrnl you will see it invoking PspCreateUserContext which takes following arguments
				//ATTENTION! this might be wrong: (Context, flag, start_address(PspUserThreadStart), thread_start_address, arguments in my case allocated_memory_thread_data)
				//now argument 4 is our thread start address right? ida says this *(_QWORD *)(a1 + 0x80) = a4; a1 being the CONTEXT meaning that context + 0x80 = Rcx
				//there ya go that's it. I highly recommend using the 1st option why? it's fucking faster even though checking this in ida also is quite fast in this case.
				thread_context.Rcx = reinterpret_cast<DWORD64>(allocated_memory_code);
#else
				//use google or a debugger for this one
				thread_context.Eax = reinterpret_cast<DWORD>(allocated_memory_code);
#endif

				if (!SetThreadContext(thread_handle, &thread_context))
					return false;

				ResumeThread(thread_handle);
			}

			if (!thread_handle)
				return false;

			WaitForSingleObject(thread_handle, INFINITE);
			CloseHandle(thread_handle);

			return true;
		}

		HANDLE thread_handle = CreateRemoteThread(process_handle, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(allocated_memory_code), allocated_memory_thread_data, NULL, nullptr);

		if (!thread_handle)
			return false;

		WaitForSingleObject(thread_handle, INFINITE);
		CloseHandle(thread_handle);

		return true;
	}

	bool Injection(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64) {

		constexpr DWORD access_flags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
		HANDLE process_handle = nullptr;

		if(additional_flags & MI_HIJACK_HANDLE)
			return HandleHijacker(pid, access_flags, exec_method, additional_flags, is_x64, Injection, injection_method, dllpath);

		const bool is_inside_hijacked_process = additional_flags & INSIDE_HIJACKED_HANDLE_PROCESS;

		if(is_inside_hijacked_process)
		{
			Utility::LoadSymbols(HandleHijackerGlobal::AdditionalArgs.path);
			process_handle = HandleHijackerGlobal::AdditionalArgs.hijacked_handle;
		}
		else
			process_handle = OpenProcess(access_flags, NULL, pid);

		if (!process_handle)
		{
			if(!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		constexpr DWORD allocation_flags = MEM_COMMIT | MEM_RESERVE;
		void* const allocated_memory_thread_data = VirtualAllocEx(process_handle, nullptr, 1 << 12, allocation_flags, PAGE_READWRITE);

		if (!allocated_memory_thread_data)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data);
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
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		Utility::IMAGE_SECTION section;
		if (!Utility::GetSectionInformation(".MIGI", &section))
			section.size_function = reinterpret_cast<ULONG_PTR>(Dummy) - reinterpret_cast<ULONG_PTR>(Shellcode);

		void* const allocated_memory_code = VirtualAllocEx(process_handle, nullptr, section.section_failed ? section.size_function : section.SizeOfRawData, allocation_flags, PAGE_EXECUTE_READ);

		if (!allocated_memory_code)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data, allocated_memory_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_memory_code, section.section_failed ? Shellcode : section.VirtualAddress, section.section_failed ? section.size_function : section.SizeOfRawData, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data, allocated_memory_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		bool status = Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, exec_method, additional_flags);

		(void)ReadProcessMemory(process_handle, allocated_memory_thread_data, &buffer, sizeof(THREAD_BUFFER), nullptr);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data, allocated_memory_code);

		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return status ? buffer.injection_status : false;
	}
}

