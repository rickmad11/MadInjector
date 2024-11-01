#include "pch.h"

#ifdef _WIN64

#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "WinTypes/VEHTypes.hpp"
#include "GenericShellcode.hpp"

/*
 * How to VEH inject
 * Download Ida pro open ntdll and load symbols from ms
 * got to exports and search for AddVectoredExceptionHandler
 * you will find RtlAddVectoredExceptionHandler -> PVOID __stdcall RtlAddVectoredExceptionHandler(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER VectoredHandler)
 * this is a wrapper for RtlpAddVectoredHandler -> void *__fastcall RtlpAddVectoredHandler(ULONG FirstHandler, void *pfVectorHandler, ULONG Type)
 * Look for LdrpVectorHandlerList this is the list that contains the vector handlers
 * Then look for NtQueryInformationProcess if you find this you will see that a local variable is being assigned a cookie and after the check if the cookie is valid it invokes
 * NtQueryInformationProcess with ProcessCookie which is of type ULONG -> NtStatus = NtQueryInformationProcess((HANDLE)0xFFFFFFFFFFFFFFFFi64, ProcessCookie, &ProcessCookie, 4u, 0i64);
 * It looks like the RtlEncodePointer function got inlined here -> PVOID __stdcall RtlEncodePointer(PVOID Pointer) it does the same shit
 * now you can switch over the RtlEncodePointer function and simply check its return -> (PVOID)__ROR8__((unsigned __int64)Pointer ^ cookie, cookie & 0x3F);
 * which will also be found in RtlpAddVectoredHandler just a bit more messy -> (void **)__ROR8__((unsigned __int64)pfVectorHandler ^ cookie, cookie & 0x3F);
 * Same applies for the part where the pointer gets Decoded now we can look where the exception handler gets invoked simply check xrefs on LdrpVectorHandlerList
 * go to RtlpCallVectoredHandlers -> bool __fastcall RtlpCallVectoredHandlers(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context, LIST_ENTRY *VectoredHandlerList)
 * Scroll a bit down and look for NtQueryInformationProcess you will find the same shit this time its just RtlDecodePointer -> PVOID __stdcall RtlDecodePointer(PVOID Pointer)
 * check return -> (PVOID)(__ROR8__(Pointer, 64 - (cookie & 0x3F)) ^ cookie);
 * or check inside RtlpCallVectoredHandlers -> decoded_pointer = (__int64 (__fastcall *)(EXCEPTION_POINTERS *))(cookie ^ __ROR8__(Pointer, 64 - (cookie & 0x3F)));
 *
 * We can either use these or DecodeRemotePointer and EncodeRemotePointer
 * Since I have a Symbol loader which makes it possible to get the addresses of not exported stuff 
 *
 * Windbg for the win:
 * 0:006> x ntdll!LdrpVectorHandlerList
 * 00007ffc`83aab408 ntdll!LdrpVectorHandlerList = <no type information>
 * 0:006> dps 00007ffc`83aab408
 * 00007ffc`83aab408  00007ffc`83a97328 ntdll!LdrpVehLock
 * 00007ffc`83aab410  00007ffc`83aab410 ntdll!LdrpVectorHandlerList+0x8
 * 00007ffc`83aab418  00007ffc`83aab410 ntdll!LdrpVectorHandlerList+0x8
 * 00007ffc`83aab420  00007ffc`83a97320 ntdll!LdrpVchLock
 * 00007ffc`83aab428  00007ffc`83aab428 ntdll!LdrpVectorHandlerList+0x20
 * 00007ffc`83aab430  00007ffc`83aab428 ntdll!LdrpVectorHandlerList+0x20
 *
 * I copied the structures online from forums and the gh injector the Dump::_RTL_SRWLOCK struct is from my own ntdll dump however using the already defined one is just fine as well
 */

namespace oVectoredExceptionHandler
{

#pragma region SHELLCODE_SEGMENT
#pragma code_seg (push)
#pragma code_seg(".VEHx")

	struct VEHBuffer
	{
		void* pShellcodeFunction = nullptr;
		PLDRP_VECTOR_HANDLER_LIST pVectorHandlerList = nullptr;
		LdrProtectMrdata pLdrProtectMrdata = nullptr;
		LIST_ENTRY o_veh_list_entry = {};
		void* manual_map_buffer = nullptr;
		void* our_veh_address = nullptr;
		void* address;
		decltype(VirtualProtect)* pVirtualProtect = nullptr;
		DWORD old_page_protection;
		bool isProcessUsingVEH = false;
		bool is_executed = false;
	};

	static LONG __stdcall ExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo, VEHBuffer* buffer)
	{
		if (!pExceptionInfo || !pExceptionInfo->ExceptionRecord || pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_GUARD_PAGE)
			return EXCEPTION_CONTINUE_SEARCH;

		if (!buffer || !buffer->pVectorHandlerList)
			return EXCEPTION_CONTINUE_SEARCH;

		//will make VectorHandlerList writable, all it does it check if true of false and calls ZwProtectVirtualMemory to make it writable.
		buffer->pLdrProtectMrdata(false);
		//loop through the doubly linked list also from gh injector since what I wrote earlier was bad and unstable xD
		for (PVECTORED_HANDLER_ENTRY current = buffer->pVectorHandlerList->FLdrpVehList; current != reinterpret_cast<void*>(&buffer->pVectorHandlerList->FLdrpVehList); current = current->Flink)
		{
			if (current == buffer->our_veh_address)
			{
				//making sure the previous VEH is not pointing to our VEH anymore and also the one after us not having a backward link to us
				//like I said it's a doubly linked list
				current->Blink->Flink = current->Flink;
				current->Flink->Blink = current->Blink;
				break;
			}
		}
		buffer->pLdrProtectMrdata(true);

		//if this flag was true before we ignore it
		if (!buffer->isProcessUsingVEH)
		{
			PEB* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
			peb->_CrossProcessFlags.ProcessUsingVEH = false;
		}

		reinterpret_cast<void(__stdcall*)(void*)>(buffer->pShellcodeFunction) (buffer->manual_map_buffer);

		//just removing the PAGE_GUARD flag
		buffer->pVirtualProtect(buffer->address, 1, buffer->old_page_protection, &buffer->old_page_protection);

		buffer->is_executed = true;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	static void __stdcall dummyb() { volatile int a = 324; } //had issues compiler optimization goes brrr

#pragma code_seg (pop)
#pragma endregion SHELLCODE_SEGMENT 

	//this will only work for &veh_list->FLdrpVehList why? bcs im lazy
	void HandleVehWriteFailure(HANDLE process_handle, LIST_ENTRY o_veh_list, void* pVehList)
	{
		MEMORY_BASIC_INFORMATION mbi {};
		(void)VirtualQueryEx(process_handle, pVehList, &mbi, sizeof(mbi));

		//this one is not being used
		DWORD old_page_protection{ 0 };

		if( (mbi.Protect & PAGE_READWRITE) == PAGE_READWRITE)
		{
			(void)WriteProcessMemory(process_handle, pVehList, &o_veh_list.Flink, sizeof(void*), nullptr);
			//iirc the vehhandler is PAGE_EXECUTE_READ should be the case im too lazy to check now so yeah....
			(void)VirtualProtectEx(process_handle, pVehList, sizeof(void*), PAGE_EXECUTE_READ, &old_page_protection);
			return;
		}

		(void)VirtualProtectEx(process_handle, pVehList, sizeof(void*), PAGE_READWRITE, &old_page_protection);
		(void)WriteProcessMemory(process_handle, pVehList, &o_veh_list.Flink, sizeof(void*), nullptr);
		(void)VirtualProtectEx(process_handle, pVehList, sizeof(void*), PAGE_EXECUTE_READ, &old_page_protection);
	}

	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data)
	{
		//LdrpVectorHandlerList is not exported so either get yourself a SmybolParser or simply manually get the address however that way you will face more issues on updates
		PLDRP_VECTOR_HANDLER_LIST const veh_list = SymbolParser::FindClass<PLDRP_VECTOR_HANDLER_LIST>("LdrpVectorHandlerList");
		LIST_ENTRY veh_list_entry{};

		//&veh_list->LdrpVehList is the same as (BYTE*)veh_list + offsetof(LDRP_VECTOR_HANDLER_LIST, LdrpVehList);
		if (!ReadProcessMemory(process_handle, &veh_list->FLdrpVehList, &veh_list_entry, sizeof(LIST_ENTRY), nullptr))
		{
			CONSOLE_LOG_ERROR("Error reading veh_list->LdrpVehList")
				return false;
		}

		const std::size_t function_size_ExceptionHandler = reinterpret_cast<DWORD64>(dummyb) - reinterpret_cast<DWORD64>(ExceptionHandler);

		void* const allocated_functionExceptionHandler = VirtualAllocEx(process_handle, nullptr, function_size_ExceptionHandler, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);

		if (!allocated_functionExceptionHandler)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed allocating memory for the Exception Handler", allocated_functionExceptionHandler);
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_functionExceptionHandler, ExceptionHandler, function_size_ExceptionHandler, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed allocating ExceptionHandler", allocated_functionExceptionHandler);
			return false;
		}

		//name is weird I know. This is our own VEH the one that is used to inject our shit
		void* const allocated_entry = VirtualAllocEx(process_handle, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_entry)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed to allocate entry", allocated_functionExceptionHandler);
			return false;
		}

		void* const allocated_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(VEHBuffer), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_buffer)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed allocating buffer", allocated_functionExceptionHandler, allocated_entry);
			return false;
		}

		void* const allocated_shellcode = VirtualAllocEx(process_handle, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);

		if (!allocated_shellcode)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed allocating shellcode", allocated_functionExceptionHandler, allocated_buffer, allocated_entry);
			return false;
		}

		//HMODULE kernel_module = GetModuleHandleW(L"Kernel32.dll");
		HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");

		//TODO add error handling
		//We get the basic info about the process so we get the address of the PEB which then can be used to read the _CrossProcessFlags member which is a union and contains a flag that tells whenever or not the process is currently
		//using an VEH.
		PROCESS_BASIC_INFORMATION process_basic_info = {};
		(void)reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(ntdll_module, "NtQueryInformationProcess")) (process_handle, PROCESSINFOCLASS::ProcessBasicInformation, &process_basic_info, sizeof(process_basic_info), nullptr);

		//for those that are not used doing &process_basic_info.PebBaseAddress->_CrossProcessFlags : it's the address that the pointer PebBaseAddress points to, then doing -> combined with & is adding PebBaseAddress + the amount of bytes
		//until we get to _CrossProcessFlags which then is the address of the union _CrossProcessFlags in the target process.
		PEB::__CrossProcessFlags CrossProcessFlags = {};
		(void)ReadProcessMemory(process_handle, &process_basic_info.PebBaseAddress->_CrossProcessFlags, &CrossProcessFlags, sizeof(ULONG), nullptr);

		//getting the protection info so we can later revert the original protection of the page.
		MEMORY_BASIC_INFORMATION mbi{};
		(void)VirtualQueryEx(process_handle, reinterpret_cast<LPVOID>(GetProcAddress(ntdll_module, "NtDelayExecution")), &mbi, sizeof(mbi));

		VEHBuffer veh_buffer{};

		veh_buffer.isProcessUsingVEH = CrossProcessFlags.ProcessUsingVEH;
		veh_buffer.old_page_protection = mbi.Protect;
		veh_buffer.address = GetProcAddress(ntdll_module, "NtDelayExecution");
		veh_buffer.pVirtualProtect = VirtualProtect;
		veh_buffer.pLdrProtectMrdata = SymbolParser::FindFunction<LdrProtectMrdata>("LdrProtectMrdata");
		veh_buffer.pShellcodeFunction = allocated_memory_code;
		veh_buffer.pVectorHandlerList = veh_list;
		veh_buffer.o_veh_list_entry = veh_list_entry;
		veh_buffer.our_veh_address = allocated_entry;
		veh_buffer.manual_map_buffer = allocated_memory_thread_data;

		if (!WriteProcessMemory(process_handle, allocated_buffer, &veh_buffer, sizeof(VEHBuffer), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing", allocated_buffer, allocated_functionExceptionHandler);
			return false;
		}

		struct ShellcodeData {
			void* pFunc = nullptr;
			void* pArgs = nullptr;
			void* pExceptionHandler = nullptr;
		}; // 24 bytes x64
		// 12 bytes x86

		unsigned char shellcode[] = { //https://defuse.ca/online-x86-assembler.htm
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sizeof(ShellcodeData) x64
			0x52,																	// push rdx
			0x53,																	// push rbx
			0x48, 0x8D, 0x1D, 0xDF, 0xFF, 0xFF, 0xFF,								// lea rbx, [rip - sizeof(ShellcodeData) - 9]
			0x48, 0x8B, 0x53, 0x08,													// mov rdx, QWORD [rbx + 0x08]
			0x48, 0x83, 0xEC, 0x08,													// sub rsp,0x08 shadow space
			0xFF, 0x53, 0x10,														// call qword ptr [rbx + 0x10]
			0x48, 0x83, 0xC4, 0x08,													// add rsp,0x08 shadow space
			0x5b,																	// pop rbx
			0x5A,																	// pop rdx
			0xC3																	// ret
		};

		reinterpret_cast<ShellcodeData*>(shellcode)->pArgs = allocated_buffer;
		reinterpret_cast<ShellcodeData*>(shellcode)->pFunc = nullptr; //never bothered to remove it lol (if you do keep in mind to adjust the shellcode)
		reinterpret_cast<ShellcodeData*>(shellcode)->pExceptionHandler = allocated_functionExceptionHandler;

		if (!WriteProcessMemory(process_handle, allocated_shellcode, shellcode, sizeof(shellcode), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		//This behaviour can also be seen in ida for instance in the RtlpCallVectoredHandlers function where it's decoding the function pointer before invoking it.
		//Therefore our address also needs to be encoded in the same way. The functions windows is using are RtlEncodePointer and RtlDecodePointer they are however inlined therefore you will not see a direct call to these function in any of the VEH functions
		void* encoded_pointer = nullptr;
		HRESULT result = reinterpret_cast<decltype(EncodeRemotePointer)*>(GetProcAddress(ntdll_module, "RtlEncodeRemotePointer")) (process_handle, reinterpret_cast<BYTE*>(allocated_shellcode) + sizeof(ShellcodeData), &encoded_pointer);

		if (result != S_OK)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "EncodeRemotePointer Failed",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		//This is going to be the new veh entry which contains our function we want to execute, we add our entry at the very beginning so that if an exception occurs our handler will be the first to handle it.
		//The original handlers will be normally invoked if we allow so, since we linked the original first handler to our entry which can be seen here -> new_veh_entry.Flink = veh_list_entry.Flink
		//NOTE: veh_list_entry is the original handler list entry.
		VECTORED_HANDLER_ENTRY new_veh_entry{};
		new_veh_entry.pfVectoredHandler = reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(encoded_pointer);
		new_veh_entry.Flink = reinterpret_cast<PVECTORED_HANDLER_ENTRY>(veh_list_entry.Flink);
		new_veh_entry.Blink = reinterpret_cast<PVECTORED_HANDLER_ENTRY>(&veh_list->FLdrpVehList); //the head of list entry 
		new_veh_entry.pDword = &reinterpret_cast<PVECTORED_HANDLER_ENTRY>(allocated_entry)->pUnknown2;
		new_veh_entry.pUnknown2 = 1;

		//The idea now is that we connect our veh entry to the beginning of the list. We replace the pointer at &LdrpVectorHandlerList->FLdrpVehList which in my case is &veh_list->FLdrpVehList with our allocated veh entry
		//after we have done that we should also make sure that the backward link of the replaced veh entry points to our entry. remember we saved the Flink to the entry that we just replaced (see above indie my new_veh_entry)
		//now the original entry which was at the beginning of FLdrpVehList still has its original stuff in there which is fine however the Blink points to the beginning of the &LdrpVectorHandlerList->FLdrpVehList which is not what we want because its now the
		//second entry in the list since we want to be the 1st one. That's why we now also have to replace the Blink with the address to our new veh entry so that the entry after us has the Blink member pointing to us.

		//Looking this up in reclass will greatly help you understand this better trust me.

		//veh_list is of type LDRP_VECTOR_HANDLER_LIST this one contains a pointer called FLdrpVehList to the very first handler entry (only if there is one obv otherwise it should point to itself again)
		//and the structure of the handler entry is this VECTORED_HANDLER_ENTRY . you can find it inside the VEHTypes.hpp otherwise just ctrl+click it in my comments yes this also works lol

		if (!WriteProcessMemory(process_handle, allocated_entry, &new_veh_entry, sizeof(VECTORED_HANDLER_ENTRY), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		//We have to do this since the page is not writable, if you opened ida you will see a function named LdrProtectMrdata which essentially just does this
		DWORD old_page_protection{ 0 };
		if (!VirtualProtectEx(process_handle, &veh_list->FLdrpVehList, sizeof(void*), PAGE_READWRITE, &old_page_protection))
		{
			HandleVehWriteFailure(process_handle, veh_list_entry, &veh_list->FLdrpVehList);
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed to Change Page Protection",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		//We are replacing the original very first entry with our new VEH entry
		if (!WriteProcessMemory(process_handle, &veh_list->FLdrpVehList, &allocated_entry, sizeof(void*), nullptr))
		{
			HandleVehWriteFailure(process_handle, veh_list_entry, &veh_list->FLdrpVehList);
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		if (!VirtualProtectEx(process_handle, &veh_list->FLdrpVehList, sizeof(void*), old_page_protection, &old_page_protection))
		{
			HandleVehWriteFailure(process_handle, veh_list_entry, &veh_list->FLdrpVehList);
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed to Change Page Protection",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		/*
		 * now since our new VEH is here we have to connect ours to the one that we just replaced, therefore we get the address of the Blink of the original value and write our VEH into the Blink,
		 * now the original VEH Blink points to ours.
		 * Also &veh_list_entry.Flink->Blink is the same as (size_t)veh_list_entry.Flink + offsetof(LDRP_VECTOR_HANDLER_LIST, Blink);
		 */
		if (!VirtualProtectEx(process_handle, &veh_list_entry.Flink->Blink, sizeof(void*), PAGE_READWRITE, &old_page_protection))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed to Change Page Protection",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		//&veh_list_entry.Flink->Blink this also requires a way to revert back to the original state after an error however I won't bother doing this I would rather crash the process than reading
		//and storing this shit value somewhere even though its just 3 lines of code. 
		if (!WriteProcessMemory(process_handle, &veh_list_entry.Flink->Blink, &allocated_entry, sizeof(void*), nullptr))
		{
			(void)WriteProcessMemory(process_handle, &veh_list->FLdrpVehList, &veh_list_entry.Blink, sizeof(void*), nullptr);
			(void)VirtualProtectEx(process_handle, &veh_list->FLdrpVehList, sizeof(void*), old_page_protection, &old_page_protection);

			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		if (!VirtualProtectEx(process_handle, &veh_list_entry.Flink->Blink, sizeof(void*), old_page_protection, &old_page_protection))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed to Change Page Protection",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		//kinda makes sense right, the process won't check the veh entries if it's not enabled. This can also be checked in ida just look for RtlpCallVectoredHandlers and you will find this
		//mov eax, [r13+50h] and bt eax, r8d. bt is nothing else than _bittest and r13 contains the PEB -> mov r13, gs:60h now looking in windbg we can see peb + 0x50 is the union +0x050 CrossProcessFlags : 2
		if (!CrossProcessFlags.ProcessUsingVEH)
		{
			CrossProcessFlags.ProcessUsingVEH = true;
			(void)WriteProcessMemory(process_handle, &process_basic_info.PebBaseAddress->_CrossProcessFlags, &CrossProcessFlags, sizeof(ULONG), nullptr);
		}

		//I got this one from the gh injector, honestly the best way to trigger this shit imo
		//remember just bcs I specified 1 doesn't mean just 1 bytes is being set to PAGE_GUARD xD it's the entire page 4kb so specifying 1 or 300 or 4096 or 1 << 12 x) will have the same effect
		DWORD old_page_protection_NtDelay = {};
		if (!VirtualProtectEx(process_handle, reinterpret_cast<LPVOID>(GetProcAddress(ntdll_module, "NtDelayExecution")), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old_page_protection_NtDelay))
		{
			HandleVehWriteFailure(process_handle, veh_list_entry, &veh_list->FLdrpVehList);
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed to Change Page Protection",
				allocated_functionExceptionHandler, allocated_entry,
				allocated_shellcode, allocated_buffer);
			return false;
		}

		//TODO this is so fucking ugly change this
		DWORD time_passed = 0;
		bool is_shellcode_executed = false;
		do
		{
			if (time_passed >= 15)
			{
				HandleVehWriteFailure(process_handle, veh_list_entry, &veh_list->FLdrpVehList);
				Utility::FreeAllocatedMemoryEx(process_handle, {},
					allocated_functionExceptionHandler, allocated_entry,
					allocated_shellcode, allocated_buffer);
				return false;
			}

			(void)ReadProcessMemory(process_handle, static_cast<BYTE*>(allocated_buffer) + offsetof(VEHBuffer, is_executed), &is_shellcode_executed, sizeof(bool), nullptr);

			++time_passed;
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		} while (!is_shellcode_executed);

		//Just in case
		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		Utility::FreeAllocatedMemoryEx(process_handle, {},
			allocated_functionExceptionHandler, allocated_entry,
			allocated_shellcode, allocated_buffer);

		return is_shellcode_executed;
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

		const std::size_t function_size_Shellcode = reinterpret_cast<DWORD64>(Dummy) - reinterpret_cast<DWORD64>(Shellcode);
		void* const allocated_functionShellcode = VirtualAllocEx(process_handle, nullptr, function_size_Shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if(!allocated_functionShellcode)
		{
			//Damn my error messages are so useful XD
			CONSOLE_LOG_ERROR("Failed Allocating Function")

			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_functionShellcode, Shellcode, function_size_Shellcode, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing", allocated_functionShellcode);

			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		void* const allocated_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(THREAD_BUFFER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_buffer)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed allocating buffer", allocated_functionShellcode);

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

		thread_buffer.additional_flags			= additional_flags;
			
		if (!WriteProcessMemory(process_handle, allocated_buffer, &thread_buffer, sizeof(THREAD_BUFFER), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed Writing", allocated_buffer, allocated_functionShellcode);

			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		bool status = Execute(process_handle, allocated_functionShellcode, allocated_buffer);

		Utility::FreeAllocatedMemoryEx(process_handle, {}, allocated_functionShellcode, allocated_buffer);

		return status;
	}
}

#endif //_WIN64