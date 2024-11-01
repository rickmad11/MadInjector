#include "pch.h"

#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "IPC/FileMappingIPC.h"
#include "GenericShellcode.hpp"

//all of these can be found in the HandleHijacker.cpp
extern std::wstring GetModuleFilePath();
extern std::uintptr_t GetModuleBaseEx(DWORD pid);

namespace oKernelCallbackTable
{

#pragma region IPC_BLOAT
	struct IPC_Data
	{
		DWORD pid{};
		bool  finished_execution = false;
	};

	void IPC_KCT()
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
			DWORD pid;
			HWND window;
		}window_info{};

		window_info.pid = data.pid;

		EnumWindows([](HWND hwnd, LPARAM fArgs) -> int
			{
				WindowInfo* winfo = reinterpret_cast<WindowInfo*>(fArgs);

				DWORD wnd_pid = 0;
				if (!GetWindowThreadProcessId(hwnd, &wnd_pid))
					return true;

				if (wnd_pid == winfo->pid)
				{
					winfo->window = hwnd;
					return false;
				}

				return true;
			}, reinterpret_cast<LPARAM>(&window_info));

		COPYDATASTRUCT cds{};
		cds.dwData = 1;
		cds.cbData = 6;
		cds.lpData = const_cast<PVOID>(reinterpret_cast<const void*>(L"yo"));
		SendMessageW(window_info.window, WM_COPYDATA, reinterpret_cast<WPARAM>(window_info.window), reinterpret_cast<LPARAM>(&cds));
		Sleep(100);

		data.finished_execution = true;
		SharedMemory.Write(&data);
		ExitProcess(0); //recommended by windows invoking TerminateProcess below is no longer requires since it will always return ERROR_ACCESS_DENIED in this case
	}

#pragma region SHELLCODE_SEGMENT_1
	struct INJECTION_ARGUMENTS
	{
		void* pfInject = nullptr;
	};

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
	void BypassSessionRestriction(HANDLE hijacked_handle, DWORD pid)
	{
		IPC_Data data{};

		FileMappingIPC SharedMemory(&data, sizeof(IPC_Data));
		if (SharedMemory.Failed())
			return;

		SharedMemory.MapFile(FILE_MAP_WRITE | FILE_MAP_READ);
		if (SharedMemory.Failed())
			return;

		data.pid = pid;
		SharedMemory.Write(&data);

		PROCESS_INFORMATION pi{};
		STARTUPINFO si{.cb = sizeof(STARTUPINFO)};

		HANDLE dup_token_handle = nullptr;
		HANDLE token_handle = nullptr;
		OpenProcessToken(hijacked_handle, TOKEN_DUPLICATE, &token_handle);
		DuplicateTokenEx(token_handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, nullptr, SecurityAnonymous, TokenPrimary, &dup_token_handle);

		if (!CreateProcessAsUserW(dup_token_handle, LR"(C:\Windows\System32\conhost.exe)", nullptr, nullptr,
			nullptr, false, CREATE_NO_WINDOW,
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
		std::uintptr_t fOffset = reinterpret_cast<std::uintptr_t>(IPC_KCT) - reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"MadInjector.dll"));
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

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		CloseHandle(dup_token_handle);
		CloseHandle(token_handle);
	}
#pragma endregion IPC_BLOAT

	/*
	 * How to get the KernelCallbackTable array/struct
	 * Step 1: Get WindDbg
	 * Step 2: Select Launch executable (make sure its one that loaded user32.dll)
	 * Step 3: Click the Green Go button
	 * Step 4: Click the Break button left to the Green Go Button or ctrl + pause on keyboard
	 * Step 5: Go onto your command line
	 * Step 6: !peb
	 * Step 7: scroll up and copy the address / or click on it xD
	 * Step 8: dt _PEB 000000b051e07000 <- skip this if you clicked on the address instead
	 * Step 9: ctrl + f look for KernelCallbackTable it should look like this :  +0x058 KernelCallbackTable : 0x00007ffe`6fc36000 Void
	 * Step 10: dt _PEB 000000b051e07000 KernelCallbackTable however the ctrl + f will also do it what we want is just the address it points to
	 * Step 11: dps 0x00007ffe6fc36000 <- is the same as dps 0x00007ffe`6fc36000
	 * Step 12: copy and paste the function names into your own array or struct however you want to do it :)
	 *
	 *  Example output on Notepad without forcing to load additional functions
	 *
	 *  0:006> dps 0x00007ffe`6fc36000
	 *	00007ffe`6fc36000  00007ffe`6fbae330 USER32!_fnCOPYDATA
	 *	00007ffe`6fc36008  00007ffe`6fc2dd20 USER32!_fnCOPYGLOBALDATA
	 *	00007ffe`6fc36010  00007ffe`6fbc3b60 USER32!_fnDWORD
	 *	00007ffe`6fc36018  00007ffe`6fbc7640 USER32!_fnNCDESTROY
	 *	00007ffe`6fc36020  00007ffe`6fba3730 USER32!_fnDWORDOPTINLPMSG
	 *	00007ffe`6fc36028  00007ffe`6fc2ea60 USER32!_fnINOUTDRAG
	 *	00007ffe`6fc36030  00007ffe`6fba25b0 USER32!_fnGETTEXTLENGTHS
	 *	00007ffe`6fc36038  00007ffe`6fc2e380 USER32!_fnINCNTOUTSTRING
	 *	00007ffe`6fc36040  00007ffe`6fc2e450 USER32!_fnINCNTOUTSTRINGNULL
	 *	00007ffe`6fc36048  00007ffe`6fc2e580 USER32!_fnINLPCOMPAREITEMSTRUCT
	 *	00007ffe`6fc36050  00007ffe`6fbc5cf0 USER32!__fnINLPCREATESTRUCT
	 *	00007ffe`6fc36058  00007ffe`6fc2e5f0 USER32!_fnINLPDELETEITEMSTRUCT
	 *	00007ffe`6fc36060  00007ffe`6fbd5710 USER32!_fnINLPDRAWITEMSTRUCT
	 *	00007ffe`6fc36068  00007ffe`6fc2e660 USER32!_fnINLPHELPINFOSTRUCT
	 *	00007ffe`6fc36070  00007ffe`6fc2e6e0 USER32!_fnINLPHLPSTRUCT
	 *	00007ffe`6fc36078  00007ffe`6fc2e800 USER32!_fnINLPMDICREATESTRUCT
	 *
	 * How to get the entire KernelCallbackTable with all the functions?
	 * simply look above at Step 11 and do dps 0x00007ffe`6fc36000 L100
	 * the 100 is a random guess from me xD L tells windbg how much he displays (afaik it means list x amount of qwords or something)
	 * After you have done this you will see a huge list of functions pointers and some trash
	 * just scroll down until you see a null somewhere 
	 *
	 * Example:
	 * 00007ffe`6fc36400  00007ffe`6fbd5890 USER32!_xxxClientCallDefWindowProc
     * 00007ffe`6fc36408  00007ffe`6fc2f2e0 USER32!_fnSHELLSYNCDISPLAYCHANGED
     * 00007ffe`6fc36410  00007ffe`6fbc5310 USER32!_fnHkINLPCHARHOOKSTRUCT
     * 00007ffe`6fc36418  00000000`00000000
     * 00007ffe`6fc36420  00007ffe`6fbbebd0 USER32!ButtonWndProcWorker
     * 00007ffe`6fc36428  00007ffe`6fbec6c0 USER32!ComboBoxWndProcWorker
     * 00007ffe`6fc36430  00007ffe`6fbbfcd0 USER32!ListBoxWndProcWorker
	 *
	 * See this null in between that is where our KCT ends
	 * however i am not 100% sure about this but thinking logically about it that should be the end, I am 99.99% sure about this
	 * if that is not the case please tell me
	 *
	 * I will not get the entire KernelCallbackTable since I will just make use of __fnCOPYDATA which should be the very first function.
	 * If your as lazy as me you could also just go onto github and paste the structure I was about to do it however I wanted to obtain the
	 * array myself
	 *
	 * Additional note:
	 * if you face issues with the symbols
	 * .symfix
	 * .reload
	 *  reload -f
	 *	Google
	 */
	
	struct KernelCallBackTableFunctions
	{
		void* _fnCOPYDATA;
		void* _fnCOPYGLOBALDATA;
		void* _fnDWORD;
		void* _fnNCDESTROY;
		void* _fnDWORDOPTINLPMSG;
		void* _fnINOUTDRAG;
		void* _fnGETTEXTLENGTHS;
		void* _fnINCNTOUTSTRING;
		void* _fnINCNTOUTSTRINGNULL;
		void* _fnINLPCOMPAREITEMSTRUCT;
		void* __fnINLPCREATESTRUCT;
		void* _fnINLPDELETEITEMSTRUCT;
		void* _fnINLPDRAWITEMSTRUCT;
		void* _fnINLPHELPINFOSTRUCT;
		void* _fnINLPHLPSTRUCT;
		void* _fnINLPMDICREATESTRUCT;
	};

	void* GetKernelCallbackTable(HANDLE process_handle)
	{
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		NtQueryInformationProcess pfNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));

		std::size_t buffer_size = sizeof(PROCESS_BASIC_INFORMATION);
		ULONG buffer_required_size = 0;
		std::unique_ptr<BYTE[]> buffer = std::make_unique_for_overwrite<BYTE[]>(buffer_size);

		do
		{
			NTSTATUS status = pfNtQueryInformationProcess(process_handle, PROCESSINFOCLASS::ProcessBasicInformation, buffer.get(), static_cast<ULONG>(buffer_size), &buffer_required_size);

			if(status == STATUS_INFO_LENGTH_MISMATCH)
			{
				buffer.reset();
				buffer_size = buffer_required_size;
				buffer = std::make_unique_for_overwrite<BYTE[]>(buffer_size);
				continue;
			}

			if(status < 0)
			{
				CONSOLE_LOG_ERROR("NtQueryInformationProcess failed")
				return nullptr;
			}

			break;
		}
		while (true);

		PROCESS_BASIC_INFORMATION* pPBI = reinterpret_cast<PROCESS_BASIC_INFORMATION*>(buffer.get());
		PEB peb{};

		if(!ReadProcessMemory(process_handle, pPBI->PebBaseAddress, &peb, sizeof(PEB), nullptr))
		{
			CONSOLE_LOG_ERROR("failed to read the peb")
			return nullptr;
		}

		return peb.KernelCallbackTable;
	}

	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, DWORD64 additional_flags, DWORD pid)
	{
		const bool is_inside_hijacked_process = additional_flags & INSIDE_HIJACKED_HANDLE_PROCESS;

		void* const pKernelCallbackTable = GetKernelCallbackTable(process_handle);

		if (!pKernelCallbackTable)
			return false;

		KernelCallBackTableFunctions kct_fns{};
		if (!ReadProcessMemory(process_handle, pKernelCallbackTable, &kct_fns, sizeof(kct_fns), nullptr))
			return false;

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

		void* shellcode_allocation = VirtualAllocEx(process_handle, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

#ifndef _WIN64
		*reinterpret_cast<DWORD**>(shellcode + 15) = reinterpret_cast<DWORD*>(shellcode_allocation);
#endif

		if (!shellcode_allocation)
			return false;

		void* const pFunction_to_inject = static_cast<BYTE*>(shellcode_allocation) + sizeof(ShellcodeData);

		if (!WriteProcessMemory(process_handle, shellcode_allocation, shellcode, sizeof(shellcode), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing Failed", shellcode_allocation);
			return false;
		}

		void* const temp__fnCOPYDATA = kct_fns._fnCOPYDATA;
		kct_fns._fnCOPYDATA = pFunction_to_inject;

		//quite risky however better than making the page RWX
		DWORD old_protection = 0;
		(void)VirtualProtectEx(process_handle, pKernelCallbackTable, sizeof(kct_fns), PAGE_READWRITE, &old_protection);

		if (!WriteProcessMemory(process_handle, pKernelCallbackTable, &kct_fns, sizeof(kct_fns), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing Failed", shellcode_allocation);
			return false;
		}

		//since this only enumerates all the windows in the current session we will have to do the same thing just as in SetWindowsHook
		//I normally would have made a single function which would cover all of my needs however I want to keep the most important parts for
		//one method inside one cpp file therefore I will make a new but very similar function for the Session switch just like in SetWindowsHook

		struct WindowInfo
		{
			DWORD pid;
			HWND window;
		}window_info{ .pid = pid };

		if (is_inside_hijacked_process)
		{
			BypassSessionRestriction(process_handle, pid);
		}
		else
		{
			EnumWindows([](HWND hwnd, LPARAM fArgs) -> int
				{
					WindowInfo* winfo = reinterpret_cast<WindowInfo*>(fArgs);

					DWORD wnd_pid = 0;
					if (!GetWindowThreadProcessId(hwnd, &wnd_pid))
						return true;

					if (wnd_pid == winfo->pid)
					{
						winfo->window = hwnd;
						return false;
					}

					return true;
				}, reinterpret_cast<LPARAM>(&window_info));

			COPYDATASTRUCT cds{};
			cds.dwData = 1;
			cds.cbData = 6;
			cds.lpData = const_cast<PVOID>(reinterpret_cast<const void*>(L"yo"));
			SendMessageW(window_info.window, WM_COPYDATA, reinterpret_cast<WPARAM>(window_info.window), reinterpret_cast<LPARAM>(&cds));
			Sleep(100);
		}

		kct_fns._fnCOPYDATA = temp__fnCOPYDATA;
		if (!WriteProcessMemory(process_handle, pKernelCallbackTable, &kct_fns, sizeof(kct_fns), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing Failed", shellcode_allocation);
			return false;
		}

		(void)VirtualProtectEx(process_handle, pKernelCallbackTable, sizeof(kct_fns), old_protection, &old_protection);

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
		constexpr DWORD access_flags = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
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

		std::size_t function_size = reinterpret_cast<DWORD64>(Dummy) - reinterpret_cast<DWORD64>(Shellcode);
		void* const allocated_code = VirtualAllocEx(process_handle, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocated_code)
		{
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_code, Shellcode, function_size, nullptr))
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

		thread_buffer.additional_flags = additional_flags;

		if (!WriteProcessMemory(process_handle, allocated_buffer, &thread_buffer, sizeof(THREAD_BUFFER), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_code, allocated_buffer);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		bool status = Execute(process_handle, allocated_code, allocated_buffer, additional_flags, pid);

		(void)ReadProcessMemory(process_handle, allocated_buffer, &thread_buffer, sizeof(THREAD_BUFFER), nullptr);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_code, allocated_buffer);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return status ? thread_buffer.injection_status : false;
	}
}
