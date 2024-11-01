#include "pch.h"

#ifdef _WIN64

#include "ExecutionMethods.hpp"

#include "GenericShellcode.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"

#pragma code_seg (push)
#pragma code_seg(".ICB")

namespace 
{
	struct ICB_DATA
	{
		void* pFunctionBuffer;
		decltype(RtlRestoreContext)* pfRtlRestoreContext = nullptr;
		bool executed = false;
		bool return_status = false;
	};

	//Don't let that rdx there confuse you it's r9 but r9 stores the original rdx before we used rdx to invoke RtlCaptureContext
	void __stdcall InstrumentationCallback(PCONTEXT const pContext, void* const pFunction, ICB_DATA* const pBuffer, DWORD64 rdx)
	{
		//checking for valid pointers is useless here since if pBuffer is invalid I won't be able to invoke RtlRestoreContext which will crash us
		//yeah manually saving registers like I did in the Thread hijacker would be better however this requires a lot less assembly

		//NtCurrentTeb is nothing but GS:[0x30]
		DWORD64 p_teb = reinterpret_cast<DWORD64>(NtCurrentTeb());

		pContext->Rip = *reinterpret_cast<DWORD64*>(p_teb + 0x02D8); //InstrumentationCallbackPreviousPc
		pContext->Rsp = *reinterpret_cast<DWORD64*>(p_teb + 0x02E0); //InstrumentationCallbackPreviousSp
		pContext->Rcx = pContext->R10; //R10 normally stores the Pc however we put r10 already into the TEB therefore we used it to save original rcx 
		pContext->Rdx = rdx; //because I used it to invoke RtlCaptureContext

		//if using syscalls in here use this
		//*reinterpret_cast<bool*>(p_teb + 0x02EC) /*InstrumentationCallbackDisabled*/ 
		//a better solution can be found below in my comments it's a github link

		//This should be enough, yeah I know multiple threads accessing this at the same time, but it works
		//when I have more time I might do it properly but for now it should be fine. after all, all I want is injecting a dll.
		//If your internal and looking to stalk the process syscalls to hide the module (even though this will probably only work on retarded usermode ac) or debugging I recommend this code
		//https://github.com/Deputation/instrumentation_callbacks/tree/master
		//was also a nice reference on how things work

		//UPDATE Future me here: should be thread safe enough now

		//https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-interlockedcompareexchange read Remarks if it's your first time seeing this.
		//that is nothing more than this instruction -> lock cmpxchg
		if(!_InterlockedCompareExchange8(reinterpret_cast<char*>(&pBuffer->executed), 1, 0))
		{
			reinterpret_cast<void(__stdcall*)(void*)>(pFunction)(pBuffer->pFunctionBuffer);
			pBuffer->return_status = true;
		}

		pBuffer->pfRtlRestoreContext(pContext, nullptr);
	}

	void __stdcall _Dummy() { std::cout << "AGAIN COMPILER!!! STOP I WANT TO FINISH THIS PROJECT"; }
}

#pragma code_seg (pop)

namespace oInstrumentationCallback
{
	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, DWORD64 additional_flags, DWORD pid)
	{
		const HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");

		//Required to set the Instrumentation callback of another process
		BOOLEAN previous_priv_b;
		reinterpret_cast<RtlAdjustPrivilege>(GetProcAddress(ntdll_module, "RtlAdjustPrivilege"))
			(/*SeDebugPrivilege = 20 ->*/ 20, true, false, &previous_priv_b);

		const DWORD64 function_size = reinterpret_cast<DWORD64>(_Dummy) - reinterpret_cast<DWORD64>(InstrumentationCallback);

		//ICB = InstrumentationCallback
		void* const allocated_ICB = VirtualAllocEx(process_handle, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocated_ICB)
		{
			CONSOLE_LOG_ERROR("Allocating memory for ICB failed")			
			return false;
		}

		if(!WriteProcessMemory(process_handle, allocated_ICB, InstrumentationCallback, function_size, nullptr))
		{
			CONSOLE_LOG_ERROR("Writing ICB into allocated memory failed")
			return false;
		}

		//I should have used the way I did stuff like I did in the Thread hijacker bcs my shellcode kinda turned terrible compared to this
		//https://gist.github.com/esoterix/df38008568c50d4f83123e3a90b62ebb
		//but his solution and the use of the context functions was too good, so I had to try to get this done somehow.

		//is this thread safe? it shouldn't be right? im talking about the way I save rdx bcs it somehow works lol, if nothing weird happens I will just move on
		//TODO if this somehow doesn't cause issues keep it otherwise make it thread safe

		BYTE shellcode[] = 
		{
			0xE9, 0x08, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,					//sizeof(rdx)
			//0x02D8 ULONG_PTR InstrumentationCallbackPreviousPc;
			0x65, 0x4C, 0x89, 0x14, 0x25, 0xD8, 0x02, 0x00, 0x00,			//mov QWORD PTR gs:0x2d8, r10 -> holds the IP (also PC stands for program counter it's the same just a different word)
			//0x02E0 ULONG_PTR InstrumentationCallbackPreviousSp;			
			0x65, 0x48, 0x89, 0x24, 0x25, 0xE0, 0x02, 0x00, 0x00,			//mov QWORD PTR gs:0x2e0, rsp
			0x49, 0x89, 0xCA,												//mov r10,rcx
			0x48, 0x89, 0x15, 0xDC, 0xFF, 0xFF, 0xFF,						//mov QWORD PTR [rip+0xffffffffffffffdc],rdx
			0x48, 0x81, 0xEC, 0xD0, 0x04, 0x00, 0x00,						//sub rsp, 0x4d0 -> sizeof(CONTEXT)
			0x48, 0x83, 0xE4, 0xF0,											//and rsp, -0x10 (align rsp to 16 bytes)
			0x48, 0x89, 0xE1,												//mov rcx, rsp -> rsp is used as buffer for the context structure -> RtlRestoreContext will revert everything 
			0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     //movabs rdx,0x0
			0xFF, 0xD2,														//call rdx
			0x48, 0x89, 0x15, 0xBB, 0xFF, 0xFF, 0xFF,						//mov rdx, QWORD PTR [rip+0xffffffffffffffbb]
			0x49, 0x89, 0xD1,												//mov r9,rdx
			0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     //movabs rdx,0x0
			0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//movabs r8,0x0
			0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		//movabs r11,0x0
			0x48, 0x83, 0xEC, 0x20,											//sub rsp,0x20
			0x41, 0xFF, 0xD3,												//call r11

			//This part is unnecessary bcs we are restoring every single register and flags in our ICB with RtlRestoreContext
			//which also means our RIP will never touch this code here. 
			0x48, 0x83, 0xC4, 0x20,											//add rsp,0x20
			0xC3															//ret
		};

		*reinterpret_cast<void**>(shellcode + 57) = RtlCaptureContext; //movabs rdx, RtlCaptureContext
		*reinterpret_cast<void**>(shellcode + 79) = allocated_memory_code; //movabs rdx, allocated_memory_code
		*reinterpret_cast<void**>(shellcode + 99) = allocated_ICB; //movabs r11,allocated_ICB

		//TODO page is rwx bcs of stupid way of saving rdx also it might not be thread safe, change shellcode make each thread wait for the ICB call so writing is fine again or take a specific thread and only allow him to execute ICB
		void* const allocated_shellcode = VirtualAllocEx(process_handle, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!allocated_shellcode)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Allocating memory for shellcode failed", allocated_ICB);
			return false;
		}

		ICB_DATA icb_data{};

		icb_data.pFunctionBuffer				= allocated_memory_thread_data;
		icb_data.pfRtlRestoreContext			= RtlRestoreContext;

		//Using the already allocated page, I don't expect ICB_DATA or the shellcode to be more than 4kb so we should be fine doing this without making any additional checks
		if (!WriteProcessMemory(process_handle, static_cast<BYTE* const>(allocated_shellcode) + sizeof(shellcode), &icb_data, sizeof(icb_data), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing ICB Data into allocated memory failed", allocated_ICB, allocated_shellcode);
			return false;
		}

		*reinterpret_cast<void**>(shellcode + 89) = static_cast<BYTE* const>(allocated_shellcode) + sizeof(shellcode); //movabs r8, icb_data

		if (!WriteProcessMemory(process_handle, allocated_shellcode, shellcode, sizeof(shellcode), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing shellcode into allocated memory failed", allocated_ICB, allocated_shellcode);
			return false;
		}

		NtSetInformationProcess pfNtSetInformationProcess		= reinterpret_cast<NtSetInformationProcess>(GetProcAddress(ntdll_module, "NtSetInformationProcess"));
		NtQueryInformationProcess pfNtQueryInformationProcess   = reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(ntdll_module, "NtQueryInformationProcess"));

		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION original_picbi {};
		(void)pfNtQueryInformationProcess(process_handle, PROCESSINFOCLASS::ProcessInstrumentationCallback, &original_picbi, sizeof(original_picbi), nullptr);

		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION fake_picbi
		{
			.Version = original_picbi.Version,
			.Reserved = original_picbi.Reserved,
			.Callback = allocated_shellcode
		};

		(void)pfNtSetInformationProcess(process_handle, PROCESSINFOCLASS::ProcessInstrumentationCallback, &fake_picbi, sizeof(fake_picbi));

		Sleep(3000);

		(void)pfNtSetInformationProcess(process_handle, PROCESSINFOCLASS::ProcessInstrumentationCallback, &original_picbi, sizeof(original_picbi));

		Sleep(100);

		bool return_status = false;
		(void)ReadProcessMemory(process_handle, &reinterpret_cast<ICB_DATA*>(static_cast<BYTE* const>(allocated_shellcode) + sizeof(shellcode))->return_status, 
			&return_status, sizeof(bool), 
			nullptr);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_ICB, allocated_shellcode);
		
		return return_status;
	}

	bool Inject(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
		constexpr DWORD access_flags = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SET_INFORMATION;
		HANDLE process_handle = nullptr;

		if (additional_flags & MI_HIJACK_HANDLE)
			return HandleHijacker(pid, access_flags, exec_method, additional_flags, is_x64, Inject, injection_method, dllpath);

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

		buffer.pfRtlInitUnicodeString	= reinterpret_cast<RtlInitUnicodeString>(GetProcAddress(ntdll_module, "RtlInitUnicodeString"));
		buffer.pfLoadLibrary			= reinterpret_cast<decltype(LoadLibraryW)*>(GetProcAddress(kernel_module, "LoadLibraryW"));
		buffer.pfLdrLoadDll				= reinterpret_cast<LdrLoadDll>(GetProcAddress(ntdll_module, "LdrLoadDll"));
		buffer.pfLdrpLoadDll			= SymbolParser::FindFunction<LdrpLoadDll>("LdrpLoadDll");
		buffer.pfLdrpLoadDllInternal	= SymbolParser::FindFunction<LdrpLoadDllInternal>("LdrpLoadDllInternal");
		buffer.pfLdrpPreprocessDllName  = SymbolParser::FindFunction<LdrpPreprocessDllName>("LdrpPreprocessDllName");

		buffer.injection_method			= injection_method;
		buffer.injection_status			= false;

		buffer.additional_flags			= additional_flags;

		memcpy_s(buffer.dllpath, sizeof(buffer.dllpath), dllpath, (std::wcslen(dllpath) * sizeof(wchar_t)) + 2);

		if (!WriteProcessMemory(process_handle, allocated_memory_thread_data, &buffer, sizeof(THREAD_BUFFER), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		const ULONG_PTR size_function = reinterpret_cast<ULONG_PTR>(Dummy) - reinterpret_cast<ULONG_PTR>(Shellcode);

		void* const allocated_memory_code = VirtualAllocEx(process_handle, nullptr, size_function, allocation_flags, PAGE_EXECUTE_READ);

		if (!allocated_memory_code)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data, allocated_memory_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_memory_code, Shellcode, size_function, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_memory_thread_data, allocated_memory_code);
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