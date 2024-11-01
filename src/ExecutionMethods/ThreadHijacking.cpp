#include "pch.h"

#include "ManualMapper/ManualMapper.hpp"
#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "SymbolParser/SymbolParser.h"
#include "GenericShellcode.hpp"

#ifdef _WIN64
#define SameTebFlags_Offset 0x17EE
#else
#define SameTebFlags_Offset 0x0FCA
#endif

namespace oThreadHijack
{
	bool IsThreadAlertable(void* thread_rip, CONTEXT const & ctx, HANDLE target_process_handle)
	{
		/*
			x86
			sp = stack pointer 
		 	[sp]      -> Return Address
			[sp + 4]  -> First  Argument 
			[sp + 8]  -> Second Argument 
			[sp + 12] -> Third  Argument

			x64 
			First  Argument = Rcx;
			Second Argument = Rdx;
			Third  Argument = R8;
			Fourth Argument = R9;

			when more than 4 arguments then the rest is pushed onto the stack
			keep in mind of the shadow space and also the fact that some calling conventions are different
			however for stdcall and fastcall in x64 it does not matter they are the same, fastcall is the standard there, this also should apply to cdecl

			therefore the below assembly applies not only to fastcall in x64

			example:

			mov     DWORD PTR [rsp+48], 7
			mov     DWORD PTR [rsp+40], 6
			mov     DWORD PTR [rsp+32], 5
			mov     r9, 4
			mov     r8, 3
			mov     rdx, 2
			mov     rcx, 1

			reading the stack pointer is also simple just rpm from rsp and you go up higher address (kinda makes sense lol) which means you get all the data on the stack
			remember stack grows to lower address throw it into a buffer or whatever and use it depending on the function to extract the arguments.
		 */
		static HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

		//we get the return address of the specific functions their size is the same since all of them are doing syscalls
		//with return address i mean the address where the ret instruction is
		static const void* const functions_to_avoid[] =
		{
			GetProcAddress(ntdll, "NtDelayExecution"),
			GetProcAddress(ntdll, "NtWaitForSingleObject"),
			GetProcAddress(ntdll, "NtWaitForMultipleObjects"),
			GetProcAddress(ntdll, "NtWaitForKeyedEvent"),
			GetProcAddress(ntdll, "NtRemoveIoCompletionEx"),
			GetProcAddress(ntdll, "NtWaitForDebugEvent"),
			GetProcAddress(ntdll, "NtReleaseKeyedEvent")
		};

		size_t function_to_inspect = 1337;
		for (size_t index = 0; index < std::size(functions_to_avoid); index++)
			if (thread_rip == reinterpret_cast<const BYTE* const>(functions_to_avoid[index]) + 0x14) //0x14 is just the offset until we hit the ret instruction from the base of the current function, you can check this in ida or cheat engine
			{
				function_to_inspect = index;
				break;
			}

		//tbh idk if the functions do something with the parameters so they r in different registers i didnt really look into that
		//im assuming that the functions are not changing the registers until we hit ret instruction however im just assuming it i didnt look into it yet
#ifdef _WIN64
		switch (function_to_inspect)
		{
			case 0: //NtDelayExecution
					return ctx.Rcx == 1;
			case 1: //NtWaitForSingleObject
					return ctx.Rdx == 1;
			//This boy right here caused me to get some threads that are not alertable idfk why
			//case 2: //NtWaitForMultipleObjects
			//		return ctx.R9 == 1;
			case 3: //NtWaitForKeyedEvent
					return ctx.R8 == 1;
			case 4: //NtRemoveIoCompletionEx
				{
					constexpr DWORD amount_of_args = 6;
					DWORD64 stack_buffer[amount_of_args];
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Rsp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[5] == 1; // last parameter which should be bool to Alertable however im not sure xD
				}
			case 5: //NtWaitForDebugEvent
					return ctx.Rdx == 1;
			case 6: //NtReleaseKeyedEvent
					return ctx.R8 == 1;

				default:
					return true;

		}
#else
		switch (function_to_inspect)
		{
			case 0: //NtDelayExecution
				{
					constexpr DWORD amount_of_args = 2;
					DWORD stack_buffer[amount_of_args + 1]; // + 1 because of return address
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[1] == 1;
				}
			case 1: //NtWaitForSingleObject
				{
					constexpr DWORD amount_of_args = 3;
					DWORD stack_buffer[amount_of_args + 1]; // + 1 because of return address
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[2] == 1;
				}
			case 2: //NtWaitForMultipleObjects
				{
					constexpr DWORD amount_of_args = 5;
					DWORD stack_buffer[amount_of_args + 1]; // + 1 because of return address
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[4] == 1;
				}
			case 3: //NtWaitForKeyedEvent
				{
					constexpr DWORD amount_of_args = 4;
					DWORD stack_buffer[amount_of_args + 1]; // + 1 because of return address
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[3] == 1;
				}
			case 4: //NtRemoveIoCompletionEx
				{
					constexpr DWORD amount_of_args = 6;
					DWORD stack_buffer[amount_of_args + 1]; // + 1 because of return address
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[5] == 1; // last parameter which should be bool to Alertable however im not sure xD
				}
			case 5: //NtWaitForAlertByThreadId
				{
					constexpr DWORD amount_of_args = 4;
					DWORD stack_buffer[amount_of_args + 1]; // + 1 because of return address
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[2] == 1; // last parameter which should be bool to Alertable however im not sure xD
				}
			case 6: //NtReleaseKeyedEvent
				{
					constexpr DWORD amount_of_args = 4;
					DWORD stack_buffer[amount_of_args + 1]; // + 1 because of return address
					if (!ReadProcessMemory(target_process_handle, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
						return false;

					return stack_buffer[3] == 1; // last parameter which should be bool to Alertable however im not sure xD
				}

			default:
				return true;

		}
#endif

		//for(const void* const current_function : functions_to_avoid)
		//	if  ( thread_rip == reinterpret_cast<const BYTE* const>(current_function) + 0x14 ) //0x14 is just the offset until we hit the ret instruction from the base of the current function, you can check this in ida or cheat engine
		//	{
		//		CONSOLE_LOG_ARGS(true,thread_rip, current_function)
		//		return false;
		//	}
	}

	std::vector<DWORD> GetThreadIDs(DWORD pid)
	{
		HANDLE snapshot_handle = nullptr;
		if(snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid); snapshot_handle == INVALID_HANDLE_VALUE || !snapshot_handle)
		{
			CONSOLE_LOG("Error Creating Snapshot of all system Threads")
			return {};
		}

		std::vector<DWORD> thread_ids;

		THREADENTRY32 thread_entry32 {.dwSize = sizeof(THREADENTRY32)};

		if(!Thread32First(snapshot_handle, &thread_entry32))
		{
			CONSOLE_LOG("Error Getting first Thread in snapshot")
			CloseHandle(snapshot_handle);
			return {};
		}

		do
		{
			if(thread_entry32.th32OwnerProcessID == pid)
				thread_ids.push_back(thread_entry32.th32ThreadID);
		} while (Thread32Next(snapshot_handle, &thread_entry32));

		CloseHandle(snapshot_handle);
		return thread_ids;
	}

	DWORD GetThreadToHijack(HANDLE target_process_handle, DWORD pid)
	{
		std::vector<DWORD> target_threads_ids { GetThreadIDs(pid) };
		if (target_threads_ids.empty())
			return false;

		NtQueryInformationThread pNtQueryInformationThread = reinterpret_cast<NtQueryInformationThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
		NtQuerySystemInformation pNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));

		DWORD64 buffer_size = 1 << 12;
		std::unique_ptr<BYTE[]> process_info_buffer = std::make_unique<BYTE[]>(buffer_size);

		//since idk how big the buffer needs to be and i dont want to oversize it we do this
		do
		{
			ULONG ReturnLength = 0;
			NTSTATUS query_status = pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, process_info_buffer.get(), sizeof(process_info_buffer[0]) * buffer_size, &ReturnLength);

			if(query_status == STATUS_INFO_LENGTH_MISMATCH)
			{
				process_info_buffer.reset();
				buffer_size = ReturnLength;
				process_info_buffer = std::make_unique<BYTE[]>(buffer_size);
				continue;
			}

			if (query_status < 0)
			{
				CONSOLE_LOG_ERROR("NtQuerySystemInformation failed")
				return 0;
			}

			break;
		}
		while (true);

		SYSTEM_PROCESS_INFORMATION* current_process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(process_info_buffer.get());

		while (reinterpret_cast<std::uintptr_t>(current_process->UniqueProcessId) != pid && current_process->NextEntryOffset)
			current_process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<BYTE*>(current_process) + current_process->NextEntryOffset);

		for (DWORD thread_id : target_threads_ids)
		{
			HANDLE thread_handle = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, false, thread_id);
			if (!thread_handle)
				continue;

			THREAD_BASIC_INFORMATION threadBI{};
			pNtQueryInformationThread(thread_handle, NT_THREAD_INFORMATION_CLASS::ThreadBasicInformation, &threadBI, sizeof(THREAD_BASIC_INFORMATION), nullptr);

			USHORT SameTebFlags {0};
			if (!ReadProcessMemory(target_process_handle, reinterpret_cast<BYTE*>(threadBI.TebBaseAddress) + SameTebFlags_Offset, &SameTebFlags, sizeof(USHORT), nullptr))
			{
				CloseHandle(thread_handle);
				continue;
			}

			SYSTEM_THREAD current_thread {};
			for (size_t index = 0; index < current_process->NumberOfThreads; index++)
				if (reinterpret_cast<std::uintptr_t>(current_process->Threads[index].ClientId.UniqueThread) == thread_id)
				{
					current_thread = current_process->Threads[index];
					break;
				}

			if(current_thread.WaitReason == KWAIT_REASON::WrQueue)
				continue;

			CONTEXT context {.ContextFlags = CONTEXT_ALL};
			GetThreadContext(thread_handle, &context);
#ifndef _WIN64
			DWORD thread_instruction_ptr = context.Eip;
#else
			DWORD64 thread_instruction_ptr = context.Rip;
#endif

			//just checking if this is a worker thread since if it is execution will take way longer it might not execute at all lol and we dont want that
			if (!static_cast<bool>(SameTebFlags & 0x2000) /*LoaderWorker*/ && (current_thread.State == static_cast<ULONG>(KTHREAD_STATE::Running)) || IsThreadAlertable(reinterpret_cast<void*>(thread_instruction_ptr), context, target_process_handle) )
			{
				CloseHandle(thread_handle);
				CONSOLE_LOG("Thread to hijack found!")
				return thread_id;
			}

			CloseHandle(thread_handle);
		}

		return 0;
	}

	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, DWORD pid, bool caller_manual_mapper)
	{
		const DWORD thread_to_hijack = GetThreadToHijack(process_handle, pid);

		if (!thread_to_hijack)
		{
			//we could still try something but i will leave it as this rn
			CONSOLE_LOG_ERROR("no ideal thread found")
				return false;
		}

		constexpr DWORD thread_access_flags = THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT; //use SYNCHRONIZE for WaitForSingleObject;
		HANDLE thread_handle = OpenThread(thread_access_flags, false, thread_to_hijack);

		struct ShellcodeData {
			void* pFunc = nullptr;
			void* pArgs = nullptr;
#ifndef _WIN64
			DWORD old_rip = 0;
#else
			DWORD64 old_rip = 0;
#endif
		}; // 24 bytes x64
		// 12 bytes x86

#ifdef _WIN64
		//i was struggling with this stuff ngl gh injector helped me a lot with all of this shellcode stuff  
		unsigned char shellcode[] = { //https://defuse.ca/online-x86-assembler.htm
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sizeof(ShellcodeData) x64
			0x50,																	// push rax
			0x51,																	// push rcx
			0x52,																	// push rdx
			0x41, 0x50,																// push r8
			0x41, 0x51,																// push r9
			0x41, 0x52,																// push r10
			0x41, 0x53,		// push	all volatile registers							// push r11
			0x9C,																	// pushf push all EFLAGS 
			0x53,																	// push rbx
			0x48, 0x8D, 0x1D, 0xD4, 0xFF, 0xFF, 0xFF,								// lea rbx, [rip - sizeof(ShellcodeData) - 20 -> this entire instr is 7 bytes and the ones before are 13 bytes]
			0x55,																	// push rbp
			0x48, 0x89, 0xE5,														// mov rbp, rsp
			0x48, 0x83, 0xE4, 0xF0,													// and rsp, -0x10 (align rsp to 16 bytes) (see below for explanation)
			0x48, 0x8B, 0x4B, 0x08,													// mov rcx, QWORD [rbx + 0x8]
			0x48, 0x83, 0xEC, 0x20,													// sub rsp,0x20 shadow space
			0xFF, 0x53, 0x00,														// call qword ptr [rbx + 0x0]
			0x48, 0x83, 0xC4, 0x20,													// add rsp,0x20 shadow space
			0x48, 0x31, 0xC0,														// xor rax, rax
			0x48, 0x89, 0xEC,														// mov rsp, rbp
			0x5D,																	// pop rbp
			0x5b,																	// pop rbx
			0x9D,																	// popfq pop all EFLAGS			
			0x41, 0x5B,																// pop r11
			0x41, 0x5A,																// pop r10
			0x41, 0x59,																// pop r9
			0x41, 0x58,																// pop r8
			0x5A,																	// pop rdx
			0x59,																	// pop rcx
			0x58,		// pop all volatile registers								// pop rax
			0x48, 0x83, 0xEC, 0x08,													// sub	rsp, 0x08				
			0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,								// mov	[rsp + 0x00], lower	
			0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,							// mov	[rsp + 0x04], higher	
			0xC3																	// ret
		};
		/*
		 *	the SP (stack pointer) needs to be an alignas of 16 bytes which means it's a multiple of 16 which then again means that the last 4 bits
		 *	must be 0, therefore we simply do -> and rsp, -0x10 which is nothing else but 0x0xFFFFFFFFFFFFFFF0 & rsp. this clears the 4 bits and preserves the rest.
		 *	btw 0x0xFFFFFFFFFFFFFFF0 in binary is 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 1111 0000
		 */
#else
		unsigned char shellcode[] = { //https://defuse.ca/online-x86-assembler.htm
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sizeof(ShellcodeData) x86
			0x60,																	// pushad
			0x9C,																	// pushf push all EFLAGS
			0x53,																	// push ebx
			0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,										// lea ebx, runtime see below
			0xFF, 0x73, 0x04,														// push DWORD PTR [ebx + 0x4]
			0xFF, 0x53, 0x00,														// call DWORD PTR [ebx + 0x0]
			0x31, 0xC0,																// xor eax, eax
			0x5B,																	// pop ebx
			0x9D,																	// popfq pop all EFLAGS	
			0x61,																	// popa
			0x48, 0x83, 0xEC, 0x04,													// sub	rsp, 0x04				
			0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,								// mov	[rsp + 0x00], Eip	
			0xC3																	// ret
		};
#endif

		void* const shellcode_allocation = VirtualAllocEx(process_handle, nullptr, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);

		if (!shellcode_allocation)
		{
			thread_handle ? CloseHandle(thread_handle) : NULL;
			return false;
		}

		if (SuspendThread(thread_handle) == (DWORD)-1)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "SuspendThread failed", shellcode_allocation);
			thread_handle ? CloseHandle(thread_handle) : NULL;
			return false;
		}

		CONTEXT thread_context{};
		thread_context.ContextFlags = CONTEXT_CONTROL; //CONTEXT_ALL would also just be fine however not necessary

		if (!GetThreadContext(thread_handle, &thread_context))
		{
			(void)ResumeThread(thread_handle);

			Utility::FreeAllocatedMemoryEx(process_handle, "GetThreadContext failed", shellcode_allocation);
			thread_handle ? CloseHandle(thread_handle) : NULL;
			return false;
		}

		ShellcodeData* const scData = reinterpret_cast<ShellcodeData*>(shellcode);
		scData->pArgs = allocated_memory_thread_data;
		scData->pFunc = allocated_memory_code;
#ifndef _WIN64
		scData->old_rip = thread_context.Eip;
#else
		scData->old_rip = thread_context.Rip;
#endif

#ifndef _WIN64
		*reinterpret_cast<DWORD**>(shellcode + sizeof(ShellcodeData) + 5) = reinterpret_cast<DWORD*>(shellcode_allocation); // ebx
		*reinterpret_cast<DWORD*>(shellcode + sizeof(ShellcodeData) + 27) = scData->old_rip; //return address

		thread_context.Eip = reinterpret_cast<DWORD>(static_cast<BYTE*>(shellcode_allocation) + sizeof(ShellcodeData));
#else
		*reinterpret_cast<DWORD*>(shellcode + sizeof(ShellcodeData) + 70) = static_cast<DWORD>(scData->old_rip & 0x00000000FFFFFFFF); // lower 
		*reinterpret_cast<DWORD*>(shellcode + sizeof(ShellcodeData) + 78) = static_cast<DWORD>(scData->old_rip >> 32); // higher

		thread_context.Rip = reinterpret_cast<DWORD64>(static_cast<BYTE*>(shellcode_allocation) + sizeof(ShellcodeData));
#endif

		if (!WriteProcessMemory(process_handle, shellcode_allocation, shellcode, sizeof(shellcode), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing memory failed", shellcode_allocation);
			thread_handle ? CloseHandle(thread_handle) : NULL;
			return false;
		}

		if (!SetThreadContext(thread_handle, &thread_context))
		{
			(void)ResumeThread(thread_handle);

			Utility::FreeAllocatedMemoryEx(process_handle, "SetThreadContext failed", shellcode_allocation);
			thread_handle ? CloseHandle(thread_handle) : NULL;
			return false;
		}

		(void)ResumeThread(thread_handle); //heh if this fails we fucked lol
		//wake the thread up just in case
		(void)PostThreadMessageW(thread_to_hijack, 0, 0, 0);
		//WaitForSingleObject(thread_handle, 500); //this would also be valid however requires SYNCHRONIZE access
		Sleep(500);

		DWORD time_passed = 0;
		bool is_shellcode_executed = false;
		bool is_injection_finished = false;

		do
		{
			if (time_passed >= 15)
			{
				Utility::FreeAllocatedMemoryEx(process_handle, {}, shellcode_allocation);
				thread_handle ? CloseHandle(thread_handle) : NULL;
				return false;
			}

#ifdef _WIN64
			if(caller_manual_mapper)
				(void)ReadProcessMemory(process_handle, static_cast<BYTE*>(allocated_memory_thread_data) + offsetof(oManualMapper::MANUAL_MAP_BUFFER, execution_finished),
					&is_shellcode_executed, sizeof(bool),
					nullptr);
#endif

			if(!caller_manual_mapper)
			{
				(void)ReadProcessMemory(process_handle, static_cast<BYTE*>(allocated_memory_thread_data) + offsetof(THREAD_BUFFER, injection_status),
					&is_injection_finished, sizeof(bool),
					nullptr);
				is_shellcode_executed = is_injection_finished;
			}

			++time_passed;
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		} while (!is_shellcode_executed);


		Utility::FreeAllocatedMemoryEx(process_handle, {}, shellcode_allocation);
		thread_handle ? CloseHandle(thread_handle) : NULL;
		return is_shellcode_executed;
	}


	bool Injection(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
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
			process_handle = OpenProcess(access_flags, false, pid);

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
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		Utility::IMAGE_SECTION section{};
		if (!Utility::GetSectionInformation(".MIGI", &section))
			section.size_function = reinterpret_cast<ULONG_PTR>(Dummy) - reinterpret_cast<ULONG_PTR>(Shellcode);

		void* const allocated_code = VirtualAllocEx(process_handle, nullptr, section.section_failed ? section.size_function : section.SizeOfRawData, allocation_flags, PAGE_EXECUTE_READ);

		if (!allocated_code)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer, allocated_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_code, section.section_failed ? Shellcode : section.VirtualAddress, section.section_failed ? section.size_function : section.SizeOfRawData, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer, allocated_code);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		bool status = Execute(process_handle, allocated_code, allocated_buffer, pid, false);

		Sleep(200);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
		NTSTATUS nt_status_return = -100;
		ReadProcessMemory(process_handle, static_cast<BYTE*>(allocated_buffer) + offsetof(THREAD_BUFFER, status), &nt_status_return, sizeof(NTSTATUS), nullptr);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_buffer, allocated_code);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return status ? NT_SUCCESS(nt_status_return) : false;
	}
}
