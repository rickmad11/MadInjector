#include "pch.h"

#include "ManualMapper/ManualMapper.hpp"
#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "GenericShellcode.hpp"

namespace oQueueUserAPC
{
	//using my already thread getter function in the thread hijacker would be the best way to do this, however im trying my best to keep the core implementation of a method inside one cpp file
	std::vector<DWORD> GetThreads(HANDLE process_handle, DWORD pid)
	{
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		const NtQuerySystemInformation pfNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
		NtQueryInformationThread pNtQueryInformationThread = reinterpret_cast<NtQueryInformationThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));

		std::size_t buffer_size = sizeof(SYSTEM_PROCESS_INFORMATION);
		ULONG required_buffer_size = 0;
		std::unique_ptr<BYTE[]> buffer = std::make_unique_for_overwrite<BYTE[]>(buffer_size);

		do
		{
			NTSTATUS status = pfNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, buffer.get(), static_cast<ULONG>(buffer_size), &required_buffer_size);

			if(status == STATUS_INFO_LENGTH_MISMATCH)
			{
				buffer.reset();
				buffer_size = required_buffer_size;
				buffer = std::make_unique_for_overwrite<BYTE[]>(buffer_size);
				continue;
			}

			if(status < 0)
			{
				CONSOLE_LOG_ERROR("NtQuerySystemInformation failed")
				return {};
			}

			break;
		}
		while (true);

		PSYSTEM_PROCESS_INFORMATION pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.get());

		for (;reinterpret_cast<std::uintptr_t>(pProcessInfo->UniqueProcessId) != pid && pProcessInfo->NextEntryOffset; pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<BYTE*>(pProcessInfo) + pProcessInfo->NextEntryOffset))
			;

		std::vector<DWORD> threads{};
		for (size_t index = 0; index < pProcessInfo->NumberOfThreads; index++)
		{
			SYSTEM_THREAD curr_thread = pProcessInfo->Threads[index];

			if (curr_thread.WaitReason == KWAIT_REASON::WrQueue)
				continue;

			HANDLE thread_handle = OpenThread(THREAD_QUERY_INFORMATION, false, reinterpret_cast<DWORD>(curr_thread.ClientId.UniqueThread));

			if (!thread_handle)
				continue;

			THREAD_BASIC_INFORMATION threadBI{};
			pNtQueryInformationThread(thread_handle, NT_THREAD_INFORMATION_CLASS::ThreadBasicInformation, &threadBI, sizeof(THREAD_BASIC_INFORMATION), nullptr);

			USHORT SameTebFlags{ 0 };
			if (!ReadProcessMemory(process_handle, reinterpret_cast<BYTE*>(threadBI.TebBaseAddress) + offsetof(TEB, SameTebFlags), &SameTebFlags, sizeof(USHORT), nullptr))
			{
				CloseHandle(thread_handle);
				continue;
			}

			if(!static_cast<bool>(SameTebFlags & 0x2000) /*LoaderWorker*/)
				threads.push_back(reinterpret_cast<DWORD>(curr_thread.ClientId.UniqueThread));

			CloseHandle(thread_handle);
		}

		return threads;
	}

	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, DWORD pid, bool caller_manual_mapper)
	{
		std::vector<DWORD> threads = GetThreads(process_handle, pid);

		if (threads.empty())
			return false;

		for (const DWORD thread : threads)
		{
			HANDLE thread_handle = OpenThread(THREAD_SET_CONTEXT, false, thread);
			if (!thread_handle)
				continue;

			if (QueueUserAPC(reinterpret_cast<PAPCFUNC>(allocated_memory_code), thread_handle, reinterpret_cast<ULONG_PTR>(allocated_memory_thread_data)))
			{
				PostThreadMessageW(thread, 0, 0, 0);

				/*
				 * The following few lines of code here are not necessary it will work without it however, why queue more apcs than we need?
				 * When my code is injected I don't see a reason to continue queueing an apc.
				 * KEEP IN MIND if you decide to not use the below additional code to early break you will have to make sure the allocated stuff
				 * is valid for every queued thread for instance if you deallocate your stuff way too fast one thread might still want to access that memory
				 * and therefore you will crash, I suggest to either wait for all the threads to execute or simply Sleep for a couple of seconds usually > 10seconds really depends on the pc and game
				 *
				 *
				 * MSDN:
				 * When a user-mode APC is queued, the thread is not directed to call the APC function unless it is in an alertable state.
				 * After the thread is in an alertable state, the thread handles all pending APCs in first in, first out (FIFO) order....
				 */

				Sleep(50);
				DWORD is_injection_finished = 0;

#ifdef _WIN64
				if(caller_manual_mapper)
					(void)ReadProcessMemory(process_handle, static_cast<BYTE*>(allocated_memory_thread_data) + offsetof(oManualMapper::MANUAL_MAP_BUFFER, execution_finished), 
						&is_injection_finished, sizeof(bool), 
						nullptr);
#endif

				if(!caller_manual_mapper)
					(void)ReadProcessMemory(process_handle, static_cast<BYTE*>(allocated_memory_thread_data) + offsetof(THREAD_BUFFER, injection_status), 
						&is_injection_finished, sizeof(bool), 
						nullptr);

				if (is_injection_finished)
					break;
			}

			CloseHandle(thread_handle);
		}

		return true;
	}

	bool Injection(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
		CONSOLE_LOG("Queue User Apc")
		constexpr DWORD access_flags = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ; 
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

		const std::size_t function_size = reinterpret_cast<DWORD64>(Dummy) - reinterpret_cast<DWORD64>(Shellcode);
		void* const allocated_code = VirtualAllocEx(process_handle, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if(!allocated_code)
		{
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		if(!WriteProcessMemory(process_handle, allocated_code, Shellcode, function_size, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		void* const allocated_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(THREAD_BUFFER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_buffer)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		THREAD_BUFFER thread_buffer{};

		memcpy_s(thread_buffer.dllpath, sizeof(thread_buffer.dllpath), dllpath, (std::wcslen(dllpath) * sizeof(wchar_t)) + 2);

		HMODULE kernel_module = GetModuleHandleW(L"Kernel32.dll");
		HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");

		thread_buffer.pfRtlInitUnicodeString	= reinterpret_cast<RtlInitUnicodeString>(GetProcAddress(ntdll_module, "RtlInitUnicodeString"));
		thread_buffer.pfLoadLibrary				= reinterpret_cast<decltype(LoadLibraryW)*>(GetProcAddress(kernel_module, "LoadLibraryW"));
		thread_buffer.pfLdrLoadDll				= reinterpret_cast<LdrLoadDll>(GetProcAddress(ntdll_module, "LdrLoadDll"));
		thread_buffer.pfLdrpLoadDll				= SymbolParser::FindFunction<LdrpLoadDll>("LdrpLoadDll");
		thread_buffer.pfLdrpLoadDllInternal		= SymbolParser::FindFunction<LdrpLoadDllInternal>("LdrpLoadDllInternal");
		thread_buffer.pfLdrpPreprocessDllName	= SymbolParser::FindFunction<LdrpPreprocessDllName>("LdrpPreprocessDllName");

		thread_buffer.injection_method			= injection_method;
		thread_buffer.injection_status			= false;
		thread_buffer.is_executed				= false;

		thread_buffer.additional_flags			= additional_flags;

		if (!WriteProcessMemory(process_handle, allocated_buffer, &thread_buffer, sizeof(THREAD_BUFFER), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_code, allocated_buffer);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		bool status = Execute(process_handle, allocated_code, allocated_buffer, pid, false);
		Sleep(100);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_code, allocated_buffer);

		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return status;
	}
}
