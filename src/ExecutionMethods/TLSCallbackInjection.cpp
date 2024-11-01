#include "pch.h"

#ifdef _WIN64

#include "ExecutionMethods.hpp"
#include "GenericShellcode.hpp"
#include "InternalFunctions.h"
#include "ThreadPoolMethod/DataTypesThreadPool.hpp"

struct TLS_SHELLCODE_DATA
{
	void* pFunction = nullptr;
	void* pFunctionArgs = nullptr;
	PIMAGE_TLS_CALLBACK* pp_tls_callbacks = nullptr;
	PIMAGE_TLS_CALLBACK p_tls_callback = nullptr;
	bool is_executed = false;
};

#pragma code_seg (push)
#pragma code_seg(".TLSMI")
#pragma optimize("", off)

static void __stdcall TLSCallbackShellcode(PVOID DllHandle, DWORD Reason, PVOID Reserved, TLS_SHELLCODE_DATA* buffer)
{
	if(!buffer->is_executed)
	{
		buffer->is_executed = true;
		reinterpret_cast<void(__stdcall*)(void*)>(buffer->pFunction)(buffer->pFunctionArgs);
	}

	//this is required to prevent recursion even though you could also just invoke the initial callback so this wouldn't be required should work as well.
	*reinterpret_cast<void**>(buffer->pp_tls_callbacks) = buffer->p_tls_callback;

	if(buffer->p_tls_callback)
		(*buffer->pp_tls_callbacks)(DllHandle, Reason, Reserved);
}

static void __stdcall dummy__() { std::cout << " "; }

#pragma optimize("", on)
#pragma code_seg (pop)

namespace oTlsCallback
{
	static BYTE* GetRemoteModuleHandle(HANDLE process_handle, PPEB p_peb, PCWSTR module_name)
	{
		PPEB_LDR_DATA p_peb_ldr_data = nullptr;
		if (!ReadProcessMemory(process_handle, &p_peb->Ldr, &p_peb_ldr_data, sizeof(PPEB_LDR_DATA), nullptr))
			return nullptr;

		LIST_ENTRY InLoadOrderModuleList = {};
		if (!ReadProcessMemory(process_handle, &p_peb_ldr_data->InLoadOrderModuleList, &InLoadOrderModuleList, sizeof(LIST_ENTRY), nullptr))
			return nullptr;

		PLIST_ENTRY curr = InLoadOrderModuleList.Flink;

		for (; curr && curr != &p_peb_ldr_data->InLoadOrderModuleList; (void)ReadProcessMemory(process_handle, &curr->Flink, &curr, sizeof(PLIST_ENTRY), nullptr))
		{
			LDR_DATA_TABLE_ENTRY ldr_data_table_entry = {};
			if (!ReadProcessMemory(process_handle, curr, &ldr_data_table_entry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))
				continue;

			WCHAR BaseDllNameBuffer[MAX_PATH];
			if (!ReadProcessMemory(process_handle, ldr_data_table_entry.BaseDllName.Buffer, BaseDllNameBuffer, MAX_PATH * 2, nullptr))
				continue;

			if(!wcscmp(BaseDllNameBuffer, module_name))
				return reinterpret_cast<BYTE*>(ldr_data_table_entry.DllBase);
		}

		return nullptr;
	}

	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, DWORD64 additional_flags, DWORD pid)
	{
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		NtSetInformationWorkerFactory pfNtSetInformationWorkerFactory		= reinterpret_cast<NtSetInformationWorkerFactory>(GetProcAddress(ntdll, "NtSetInformationWorkerFactory"));
		NtQueryInformationWorkerFactory pfNtQueryInformationWorkerFactory	= reinterpret_cast<NtQueryInformationWorkerFactory>(GetProcAddress(ntdll, "NtQueryInformationWorkerFactory"));
		NtQueryInformationProcess pfNtQueryInformationProcess				= reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));

		PROCESS_BASIC_INFORMATION pbi{};
		(void)pfNtQueryInformationProcess(process_handle, _PROCESSINFOCLASS::ProcessBasicInformation, &pbi, sizeof pbi, nullptr);

		BYTE* image_base = GetRemoteModuleHandle(process_handle, pbi.PebBaseAddress, L"KERNELBASE.dll");

		PIMAGE_DOS_HEADER p_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

		LONG e_lfanew = 0;
		if (!ReadProcessMemory(process_handle, &p_dos_header->e_lfanew, &e_lfanew, sizeof(LONG), nullptr))
			return false;

		IMAGE_NT_HEADERS nt_header{};
		if (!ReadProcessMemory(process_handle, (image_base + e_lfanew), &nt_header, sizeof(nt_header), nullptr))
			return false;
		
		IMAGE_TLS_DIRECTORY tls_directory{};
		if (!ReadProcessMemory(process_handle, (nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + image_base), &tls_directory, sizeof(tls_directory), nullptr))
			return false;
		
		PIMAGE_TLS_CALLBACK* pp_tls_callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls_directory.AddressOfCallBacks);

		//p_tls_callback can be null actually I think it will always be null in this case since we are using kernelbase the reason for this is
		//it has tls callbacks however there are none registered so it's an array of 1 tls callback that is a nullptr that means we only need to check if the tls callback is valid in our shellcode
		//and it should grant us the ability to use this in almost every process.
		//If this should not be the case anymore in the future I would just walk all modules and check if any of them have any tls callbacks.
		PIMAGE_TLS_CALLBACK p_tls_callback = nullptr;
		if (!ReadProcessMemory(process_handle, pp_tls_callback, &p_tls_callback, sizeof(p_tls_callback), nullptr))
		{
			if(reinterpret_cast<DWORD64>(pp_tls_callback) == 64LL)
				CONSOLE_LOG_ERROR("cannot execute code because the process has no tls callbacks")
			else
				CONSOLE_LOG_ERROR("reading tls callbacks array failed")
			return false;
		}

		DWORD64 function_size = reinterpret_cast<DWORD64>(dummy__) - reinterpret_cast<DWORD64>(TLSCallbackShellcode);
		void* const allocated_tls_callback_function = VirtualAllocEx(process_handle, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		void* const allocated_tls_data = VirtualAllocEx(process_handle, nullptr, sizeof(TLS_SHELLCODE_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if(!allocated_tls_callback_function || !allocated_tls_data)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed allocating one of the following: shellcode or tls data", allocated_tls_callback_function, allocated_tls_data);
			return false;
		}

		TLS_SHELLCODE_DATA tls_sc_data {};
		tls_sc_data.pp_tls_callbacks				= pp_tls_callback;
		tls_sc_data.p_tls_callback					= p_tls_callback;
		tls_sc_data.pFunctionArgs					= allocated_memory_thread_data;
		tls_sc_data.pFunction						= allocated_memory_code;

		if (!WriteProcessMemory(process_handle, allocated_tls_data, &tls_sc_data, sizeof(TLS_SHELLCODE_DATA), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing tls shellcode data", allocated_tls_callback_function, allocated_tls_data);
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_tls_callback_function, TLSCallbackShellcode, function_size, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing tls shellcode", allocated_tls_callback_function, allocated_tls_data);
			return false;
		}

		BYTE shellcode[] = 
		{
			//rcx, rdx, r8 are reserved for PVOID DllHandle, DWORD Reason, PVOID Reserved
			0x50,																	// push rax
			0x51,																	// push rcx
			0x52,																	// push rdx
			0x41, 0x50,																// push r8
			0x41, 0x51,																// push r9
			0x41, 0x52,																// push r10
			0x41, 0x53,																// push r11
			0x9C,																	// pushf push all EFLAGS 
			0x53,																	// push rbx
			0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				//movabs r9,buffer
			0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,				//movabs r10, shellcode function
			0x48, 0x83, 0xE4, 0xF0,													//and rsp,-0x10
			0x48, 0x83, 0xEC, 0x20,													//sub rsp,0x20
			0x41, 0xFF, 0xD2,														//call r10
			0x48, 0x83, 0xC4, 0x20,													//add rsp,0x20
			0x5b,																	// pop rbx
			0x9D,																	// popfq pop all EFLAGS			
			0x41, 0x5B,																// pop r11
			0x41, 0x5A,																// pop r10
			0x41, 0x59,																// pop r9
			0x41, 0x58,																// pop r8
			0x5A,																	// pop rdx
			0x59,																	// pop rcx
			0x58,																	// pop rax
			0xC3
		};

		*reinterpret_cast<void**>(shellcode + 15) = allocated_tls_data;
		*reinterpret_cast<void**>(shellcode + 25) = allocated_tls_callback_function;

		//using the allocated page from the function which should be enough for the shellcode for now.
		if(!WriteProcessMemory(process_handle, reinterpret_cast<BYTE*>(allocated_tls_callback_function) + function_size, shellcode, sizeof(shellcode), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing shellcode", allocated_tls_callback_function, allocated_tls_data);
			return false;
		}

		DWORD old_page_protection = NULL;
		//don't let that 1 confused you like I mentioned somewhere else in my code this will always change the entire page 4kb not just 1 byte that won't work
		if(!VirtualProtectEx(process_handle, pp_tls_callback, 1, PAGE_READWRITE, &old_page_protection))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed changing page protection", allocated_tls_callback_function, allocated_tls_data);
			return false;
		}

		void* const entry = (reinterpret_cast<BYTE*>(allocated_tls_callback_function) + function_size);

		//changing first tls callback entry
		if (!WriteProcessMemory(process_handle, pp_tls_callback, &entry, sizeof(void*), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing allocated_shellcode to tls callback", allocated_tls_callback_function, allocated_tls_data);
			return false;
		}

		//triggering a new thread to be created so our callback is being invoked
		//idea from him https://urien.gitbook.io/diago-lima/abusing-tls-callbacks-for-payload-execution
		HANDLE tp_wf_handle = oThreadPool::GetHandleOfType(L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS, process_handle, pid);

		WORKER_FACTORY_BASIC_INFORMATION wfbi{};
		(void)pfNtQueryInformationWorkerFactory(tp_wf_handle, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi), nullptr);

		ULONG new_minimum_threads = wfbi.TotalWorkerCount + 1;
		(void)pfNtSetInformationWorkerFactory(tp_wf_handle, WorkerFactoryThreadMinimum, &new_minimum_threads, sizeof(ULONG));

		Sleep(2000);

		(void)pfNtSetInformationWorkerFactory(tp_wf_handle, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi));
		CloseHandle(tp_wf_handle);

		//reverting back to original stuff even though we already did this to prevent recursion in our shellcode
		if (!WriteProcessMemory(process_handle, pp_tls_callback, &p_tls_callback, sizeof(void*), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing allocated_shellcode to tls callback", allocated_tls_callback_function, allocated_tls_data);
			return false;
		}

		(void)VirtualProtectEx(process_handle, pp_tls_callback, 1, old_page_protection, &old_page_protection);

		bool status = false;
		(void)ReadProcessMemory(process_handle, &reinterpret_cast<TLS_SHELLCODE_DATA*>(allocated_tls_data)->is_executed, &status, 1, nullptr);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tls_callback_function, allocated_tls_data);

		return status;
	}

	bool Injection(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
		constexpr DWORD access_flags = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
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

		bool status = Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, additional_flags, pid);

		(void)ReadProcessMemory(process_handle, allocated_memory_thread_data, &buffer, sizeof(THREAD_BUFFER), nullptr);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data, allocated_memory_code);

		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return status ? buffer.injection_status : false;
	}
}

#endif