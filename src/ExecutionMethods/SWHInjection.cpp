#include "pch.h"

#include <thread>

#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "IPC/FileMappingIPC.h"
#include "SymbolParser/SymbolParser.h"
#include "GenericShellcode.hpp"

//all of these can be found in the HandleHijacker.cpp
extern std::wstring GetModuleFilePath();
extern std::uintptr_t GetModuleBaseEx(DWORD pid);

namespace oSetWindowsHook
{
	struct IPC_Data
	{
		DWORD pid{};
		void* pFunction_to_inject = nullptr;
		bool  finished_execution = false;
	};

	void IPC_SetWindowsHook()
	{
		IPC_Data data{};
		
		FileMappingIPC SharedMemory(sizeof(data));
		if (SharedMemory.Failed())
			return;

		SharedMemory.MapFile(FILE_MAP_READ | FILE_MAP_WRITE);
		if (SharedMemory.Failed())
			return;

		SharedMemory.Read(&data);

		struct WindowInfo
		{
			DWORD thread_id;
			DWORD pid;
			HWND window;
		}window_info{};
	
		window_info.pid = data.pid;
	
		EnumWindows([](HWND window, LPARAM ThreadId) -> int
			{
				WindowInfo* winfo = reinterpret_cast<WindowInfo*>(ThreadId);
	
				DWORD out_pid;
				DWORD current_thread_id = GetWindowThreadProcessId(window, &out_pid);
	
				wchar_t window_class_name[MAX_PATH];
				GetWindowTextW(window, window_class_name, MAX_PATH);
	
				if (GetClassNameW(window, window_class_name, MAX_PATH) &&
					wcscmp(window_class_name, L"ConsoleWindowClass") != 0 &&
					out_pid == winfo->pid)
				{
					GUITHREADINFO gui_thread_info{ .cbSize = sizeof(GUITHREADINFO) };
					if (GetGUIThreadInfo(current_thread_id, &gui_thread_info))
					{
						winfo->thread_id = current_thread_id;
						winfo->window = window;
						return false;
					}
					CONSOLE_LOG_ERROR("The Thread that created the window is not a GUI Thread enumerate all threads to get the correct one!")
						return true;
				}
	
				return true;
			}, reinterpret_cast<LPARAM>(&window_info));
	
	
		HINSTANCE ntdll_handle = GetModuleHandleW(L"ntdll.dll");
	
		HHOOK hook_handle = SetWindowsHookExW(WH_CALLWNDPROC, static_cast<HOOKPROC>(data.pFunction_to_inject), ntdll_handle, window_info.thread_id);
	
		SendMessageW(window_info.window, WM_KEYDOWN, VK_SPACE, 0);
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	
		UnhookWindowsHookEx(hook_handle);

		data.finished_execution = true;
		SharedMemory.Write(&data);

	}

#pragma region SHELLCODE_SEGMENT_1
	struct INJECTION_ARGUMENTS
	{
		void* pfInject = nullptr;
	};

	//since i fucked up early in my code we need this to make it work
#pragma code_seg (push)
#pragma code_seg(".ISrc2")
	static void IPCShellcode(INJECTION_ARGUMENTS* pArgs)
	{
		reinterpret_cast<void(__fastcall*)(void)>(pArgs->pfInject)();
	}

	static void dummy_yo() {}
#pragma code_seg (pop)
#pragma endregion SHELLCODE_SEGMENT_1

	//Supports session 0 process (which usually has the handle to the target) to work with Session 1 processes with SetWindowsHook.
	void BypassSessionRestriction(HANDLE hijacked_handle, DWORD pid, HOOKPROC pFunction_to_inject)
	{
		IPC_Data data{};

		FileMappingIPC SharedMemory(&data, sizeof(IPC_Data));
		if (SharedMemory.Failed())
			return;

		SharedMemory.MapFile(FILE_MAP_WRITE | FILE_MAP_READ);
		if (SharedMemory.Failed())
			return;

		data.pid = pid;
		data.pFunction_to_inject = pFunction_to_inject;
		SharedMemory.Write(&data);

		PROCESS_INFORMATION pi {};
		STARTUPINFO si{ .cb = sizeof(STARTUPINFO) };

		HANDLE dup_token_handle = nullptr;
		HANDLE token_handle = nullptr;
		OpenProcessToken(hijacked_handle, TOKEN_DUPLICATE, &token_handle);
		//we need DuplicateTokenEx in case the token won't let us get the access rights we want, also we need a primary token which is not guaranteed. you can read on msdn its checking the DACL if request is ok or not
		DuplicateTokenEx(token_handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, nullptr, SecurityAnonymous, TokenPrimary, &dup_token_handle);

		if (!CreateProcessAsUserW(dup_token_handle, LR"(C:\Windows\System32\conhost.exe)", nullptr, nullptr,
			nullptr, false, 0,
			nullptr, nullptr, &si, &pi))
		{
			CloseHandle(dup_token_handle);
			CloseHandle(token_handle);
			return;
		}

		auto cleanup_return = [&dup_token_handle, &token_handle, &pi]
		<typename... Args> requires (std::conjunction_v<std::is_pointer<Args>...>)
		(Args... args) -> void
		{
			if constexpr (sizeof...(args) > 0)
				Utility::FreeAllocatedMemoryEx(pi.hProcess, "", args...);

			(void)TerminateProcess(pi.hProcess, 0);

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			CloseHandle(dup_token_handle);
			CloseHandle(token_handle);
		};

		DWORD64 function_size = reinterpret_cast<DWORD64>(dummy_yo) - reinterpret_cast<DWORD64>(IPCShellcode);

		void* allocated_memory_code = VirtualAllocEx(pi.hProcess, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocated_memory_code)
			return cleanup_return();

		if (!WriteProcessMemory(pi.hProcess, allocated_memory_code, IPCShellcode, function_size, nullptr))
			return cleanup_return(allocated_memory_code);

		void* allocated_memory_buffer = VirtualAllocEx(pi.hProcess, nullptr, sizeof(INJECTION_ARGUMENTS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_memory_buffer)
			return cleanup_return(allocated_memory_code);

		std::wstring dllpath = GetModuleFilePath();

		if (dllpath.empty())
			return cleanup_return(allocated_memory_code, allocated_memory_buffer);

		//injecting our own dll into the created process which happens to be conhost.exe in my case 
		bool ret_status = oCreateThread::Injection(dllpath.c_str(), pi.dwProcessId,
			Injection_Method::_LoadLibrary, L"NtCreateThreadEx",
			MI_THREAD_START_ADDRESS_SPOOF | MI_THREAD_HIDE_FROM_DEBUGGER, true);

		if (!ret_status)
			return cleanup_return(allocated_memory_code, allocated_memory_buffer);

		INJECTION_ARGUMENTS fArgs{};
		std::uintptr_t fOffset = reinterpret_cast<std::uintptr_t>(IPC_SetWindowsHook) - reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"MadInjector.dll"));
		fArgs.pfInject = reinterpret_cast<void*>(GetModuleBaseEx(pi.dwProcessId) + fOffset);

		if (!WriteProcessMemory(pi.hProcess, allocated_memory_buffer, &fArgs, sizeof(INJECTION_ARGUMENTS), nullptr))
			return cleanup_return(allocated_memory_code, allocated_memory_buffer);

		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		const NtCreateThreadEx pfNtCreateThreadEx = reinterpret_cast<NtCreateThreadEx>(GetProcAddress(ntdll, "NtCreateThreadEx"));

		HANDLE thread_handle = nullptr;

		(void)pfNtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS,
			nullptr, pi.hProcess,
			reinterpret_cast<PUSER_THREAD_START_ROUTINE>(allocated_memory_code), allocated_memory_buffer,
			THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0,
			0, 0,
			nullptr);

		if (!thread_handle)
			return cleanup_return(allocated_memory_code, allocated_memory_buffer);
		
		WaitForSingleObject(thread_handle, 5000);
		CloseHandle(thread_handle);

		//just making sure since if we go out of scope my FileMapping destructor will be invoked
		SharedMemory.Read(&data);
		if (!data.finished_execution)
			Sleep(3000);

		(void)TerminateProcess(pi.hProcess, 0);

		//deallocating the stuff is not required since we kill the process. Now im realizing calling virtualfree is not required at all here lol whatever

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		CloseHandle(dup_token_handle);
		CloseHandle(token_handle);
	}

	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, DWORD64 additional_flags, DWORD pid)
	{
		const bool is_inside_hijacked_process = additional_flags & INSIDE_HIJACKED_HANDLE_PROCESS;

		struct ShellcodeData {
			void* pFunc = nullptr;
			void* pArgs = nullptr;
			bool is_executed = false;
		}; // 24 bytes x64
		// 12 bytes x86

#ifdef _WIN64
		unsigned char shellcode[] = { //https://defuse.ca/online-x86-assembler.htm
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sizeof(ShellcodeData) x64
			0x53,					// push rbx
			0x48, 0x8D, 0x1D, 0xE0, 0xFF, 0xFF, 0xFF, //lea rbx, [rip - sizeof(ShellcodeData) - 8 -> this entire instr is 7 bytes and the one before is 1 byte]	
			0x80, 0x7B, 0x10, 0x00, // cmp BYTE PTR [rbx+0x10],0x0
			0x75, 0x13,				// jne 19 bytes
			0xC6, 0x43, 0x10, 0x01, // mov BYTE PTR [rbx+0x10],0x1
			0x48, 0x8B, 0x4B, 0x08, // mov rcx, QWORD [rbx + 0x8]
			0x48, 0x83, 0xEC, 0x20, // sub rsp,0x20 shadow space
			0xFF, 0x53, 0x00,		// call qword ptr [rbx + 0x0]
			0x48, 0x83, 0xC4, 0x20, // add rsp,0x20 shadow space
			0x48, 0x31, 0xC0,		// xor rax, rax
			0x5b,					// pop rbx
			0xC3                    // ret
		};
#else
		unsigned char shellcode[] = { //https://defuse.ca/online-x86-assembler.htm
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sizeof(ShellcodeData) x86
			0x60,					  // pushad
			0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00, // lea ebx, runtime see below
			0x80, 0x7B, 0x08, 0x00,   // cmp BYTE PTR [ebx+0x08],0x0
			0x75, 0x0A,               // jne 10 bytes
			0xC6, 0x43, 0x08, 0x01,   // mov BYTE PTR [ebx+0x08],0x1
			0xFF, 0x73, 0x04,         // push DWORD PTR [ebx+0x4]
			0xFF, 0x53, 0x00,         // call DWORD PTR [ebx + 0x0]
			0x31, 0xC0,               // xor eax, eax
			0x5B,                     // pop ebx
			0x61,					  // popa 
			0xC3					  // ret
		};
#endif

		ShellcodeData* const scData = reinterpret_cast<ShellcodeData*>(shellcode);
		scData->pArgs = allocated_memory_thread_data;
		scData->pFunc = allocated_memory_code;
		scData->is_executed = false;

		void* const shellcode_allocation = VirtualAllocEx(process_handle, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

#ifndef _WIN64
		* reinterpret_cast<DWORD**>(shellcode + 15) = reinterpret_cast<DWORD*>(shellcode_allocation);
#endif

		if (!shellcode_allocation)
			return false;

		HOOKPROC pFunction_to_inject = reinterpret_cast<HOOKPROC>(static_cast<BYTE*>(shellcode_allocation) + sizeof(ShellcodeData));

		if (!WriteProcessMemory(process_handle, shellcode_allocation, shellcode, sizeof(shellcode), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing", shellcode_allocation);
			return false;
		}

		/*
		 *	There are way better approaches to this and tbh mine is the worst (for better approaches refer to any other source xD my favorite https://github.com/guided-hacking/GuidedHacking-Injector I learned a lot from his source).
		 *	I am not focused to make my injector work for as many people as possible this injector was intended for myself. I will not bother making my stuff work for people that have a computer with multiple users and
		 *	have multiple sessions, since im the only user on my pc I only have the system session 0 and the user session 1. Usually you would want to do something like this: OpenProcessToken from the target DuplicateTokenEx and then CreateProcessAsUser
		 *	that is how you launch something with the desired session id. Update: turns our I kinda need it, makes my life easier, also for lazy people like me that don't want to make a separate
		 *	project for the session 1 exe just use conhost.exe in System32 way easier imo, cmd.exe is not recommended since you will encounter issues believe me cmd.exe is a coin flip xD
		 */

		if (is_inside_hijacked_process)
		{
			BypassSessionRestriction(process_handle, pid, pFunction_to_inject); // not a bypass xD but I could not think of a better name 
		}
		else
		{
			struct WindowInfo
			{
				DWORD thread_id;
				DWORD pid;
				HWND window;
			}window_info{};

			window_info.pid = pid;

			EnumWindows([](HWND window, LPARAM ThreadId) -> int
				{
					WindowInfo* winfo = reinterpret_cast<WindowInfo*>(ThreadId);

					DWORD out_pid;
					DWORD current_thread_id = GetWindowThreadProcessId(window, &out_pid);

					wchar_t window_class_name[MAX_PATH];
					GetWindowTextW(window, window_class_name, MAX_PATH);

					if (GetClassNameW(window, window_class_name, MAX_PATH) &&
						wcscmp(window_class_name, L"ConsoleWindowClass") != 0 &&
						out_pid == winfo->pid)
					{
						GUITHREADINFO gui_thread_info{ .cbSize = sizeof(GUITHREADINFO) };
						if (GetGUIThreadInfo(current_thread_id, &gui_thread_info))
						{
							winfo->thread_id = current_thread_id;
							winfo->window = window;
							return false;
						}
						CONSOLE_LOG_ERROR("The Thread that created the window is not a GUI Thread enumerate all threads to get the correct one!")
						return true;
					}

					return true;
				}, reinterpret_cast<LPARAM>(&window_info));

			HINSTANCE ntdll_handle = GetModuleHandleW(L"ntdll.dll");

			HHOOK hook_handle = SetWindowsHookExW(WH_CALLWNDPROC, pFunction_to_inject, ntdll_handle, window_info.thread_id);

			SendMessageW(window_info.window, WM_KEYDOWN, VK_SPACE, 0);
			std::this_thread::sleep_for(std::chrono::milliseconds(50));

			UnhookWindowsHookEx(hook_handle);
		}

		DWORD time_passed = 0;
		bool is_shellcode_executed = false;
		do
		{
			if (time_passed >= 15)
			{
				Utility::FreeAllocatedMemoryEx(process_handle, {}, shellcode_allocation);
				return false;
			}

			ReadProcessMemory(process_handle, static_cast<BYTE*>(shellcode_allocation) + offsetof(ShellcodeData, is_executed), &is_shellcode_executed, sizeof(bool), nullptr);

			++time_passed;
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		} while (!is_shellcode_executed);

		Utility::FreeAllocatedMemoryEx(process_handle, {}, shellcode_allocation);
		return is_shellcode_executed;
	}

	bool Injection(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
		constexpr DWORD access_flags = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;
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

		constexpr DWORD allocation_flags = MEM_COMMIT | MEM_RESERVE;
		void* const allocated_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(THREAD_BUFFER), allocation_flags, PAGE_READWRITE);

		if (!allocated_buffer)
		{
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		THREAD_BUFFER buffer;

		memcpy_s(buffer.dllpath, sizeof(buffer.dllpath), dllpath, (std::wcslen(dllpath) * sizeof(wchar_t)) + 2);

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

		if (!WriteProcessMemory(process_handle, allocated_buffer, &buffer, sizeof(THREAD_BUFFER), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		Utility::IMAGE_SECTION section;
		//I know specifying the namespace Utility here is not needed anymore however this might confuse others who don't know about this
		if (!Utility::GetSectionInformation(".MIGI", &section))
			section.size_function = reinterpret_cast<ULONG_PTR>(Dummy) - reinterpret_cast<ULONG_PTR>(Shellcode);

		void* const allocated_memory_code = VirtualAllocEx(process_handle, nullptr, section.section_failed ? section.size_function : section.SizeOfRawData, allocation_flags, PAGE_EXECUTE_READ);

		if (!allocated_memory_code)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer, allocated_memory_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_memory_code, section.section_failed ? Shellcode : section.VirtualAddress, section.section_failed ? section.size_function : section.SizeOfRawData, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer, allocated_memory_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		bool status = Execute(process_handle, allocated_memory_code, allocated_buffer, additional_flags, pid);

		(void)ReadProcessMemory(process_handle, allocated_buffer, &buffer, sizeof(THREAD_BUFFER), nullptr);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer, allocated_memory_code);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return status ? buffer.injection_status : false;
	}
}