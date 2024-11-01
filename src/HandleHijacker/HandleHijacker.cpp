#include "pch.h"

#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"

#ifdef _WIN64
#define OWN_MODULE_NAME L"MadInjector.dll"
#else
#define OWN_MODULE_NAME L"MadInjectorX86.dll"
#endif

struct TARGET_HANDLE_INFO
{
	DWORD UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
};

static bool IsProcessHandle(HANDLE handle_to_duplicate, NtQueryObject pfNtQueryObject)
{
	ULONG buffer_size = 1 << 12;
	std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(buffer_size);

	ULONG required_buffer_size = 0;

	do
	{
		NTSTATUS status = pfNtQueryObject(handle_to_duplicate, OBJECT_INFORMATION_CLASS::ObjectTypeInformation, buffer.get(), buffer_size, &required_buffer_size);

		if(status == STATUS_INFO_LENGTH_MISMATCH)
		{
			buffer.reset();
			buffer_size = required_buffer_size;
			buffer = std::make_unique<BYTE[]>(buffer_size);
			continue;
		}

		if(status < 0)
			return false; //this will fail very often which is fine therefore i wont print anything here

		break;
	}
	while (true);

	POBJECT_TYPE_INFORMATION oti = reinterpret_cast<POBJECT_TYPE_INFORMATION>(buffer.get());

	//member Length is in bytes not the amount of characters thats why / sizeof(wchar_t)
	std::wstring object_type(oti->TypeName.Buffer, oti->TypeName.Length / sizeof(wchar_t));
	if (object_type == L"Process")
	{
		CONSOLE_LOG_ARGS(false, "Handle type: ", object_type.c_str())
		return true;
	}

	return false;
}

static std::vector<TARGET_HANDLE_INFO> FindHandlesToHijack(DWORD target_pid, DWORD desired_handle_access_flags)
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	const NtQuerySystemInformation pfNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
	const NtQueryObject pfNtQueryObject = reinterpret_cast<NtQueryObject>(GetProcAddress(ntdll, "NtQueryObject"));

	//yes this is necessary I checked all process handles to the target and compared it with and without using RtlAdjustPrivilege in ProcessExplorer and I found all of them when using RtlAdjustPrivilege
	//yes I ran my process as admin still different results when using RtlAdjustPrivilege
	//also the last parameter has to be a valid address you cannot pass nullptr to it
	BOOLEAN previous_priv_b; // Whether privilege was previously enabled or disabled.
	const RtlAdjustPrivilege pfRtlAdjustPrivilege = reinterpret_cast<RtlAdjustPrivilege>(GetProcAddress(ntdll, "RtlAdjustPrivilege"));
	pfRtlAdjustPrivilege(20, true, false, &previous_priv_b);

	ULONG buffer_size = 1 << 12;
	std::unique_ptr<BYTE[]> buffer = std::make_unique<BYTE[]>(buffer_size);

	ULONG required_buffer_size = 0;
	do
	{
		NTSTATUS status = pfNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemHandleInformation, buffer.get(), buffer_size, &required_buffer_size);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			buffer.reset();
			buffer_size = required_buffer_size;
			buffer = std::make_unique<BYTE[]>(buffer_size);
			continue;
		}

		if (status < 0)
		{
			CONSOLE_LOG_ERROR("NtQuerySystemInformation failed")
			return {};
		}

		break;
	} while (true);

	DWORD own_pid = GetCurrentProcessId();
	HANDLE own_pseudo_handle = GetCurrentProcess();

	std::vector<TARGET_HANDLE_INFO> v_handles;

	PSYSTEM_HANDLE_INFORMATION shi = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer.get());
	for (size_t handle_index = 0; handle_index < shi->NumberOfHandles; handle_index++)
	{
		//we ignore all of the handles from our application and the target
		if (shi->Handles[handle_index].UniqueProcessId == own_pid || shi->Handles[handle_index].UniqueProcessId == target_pid)
			continue;
		
		//checking if the current handle permissions are PROCESS_ALL_ACCESS
		if ((shi->Handles[handle_index].GrantedAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
			goto CHECK_IF_HANDLE_OK;

		//checking if the current handle permissions are whatever we passed to our function
		if ((shi->Handles[handle_index].GrantedAccess & desired_handle_access_flags) != desired_handle_access_flags)
			continue;

	CHECK_IF_HANDLE_OK:

		HANDLE handle_to_duplicate = reinterpret_cast<HANDLE>(shi->Handles[handle_index].HandleValue);

		//this is a handle to whoever owns this handle currently
		HANDLE handle_to_current_handle_owner = OpenProcess(PROCESS_DUP_HANDLE, false, shi->Handles[handle_index].UniqueProcessId);

		if (!handle_to_current_handle_owner)
			continue;

		HANDLE duplicated_handle = nullptr;

		//we have to duplicate the handle otherwise we won't be able to check whenever or not the handle of the current process had a open handle to our target process
		if (!DuplicateHandle(handle_to_current_handle_owner, handle_to_duplicate, own_pseudo_handle, &duplicated_handle, PROCESS_QUERY_LIMITED_INFORMATION, false, 0))
		{
			CloseHandle(handle_to_current_handle_owner);
			continue;
		}

		//this is where we are now able to check if the handle is actually an opened one to our target, since the duplicated handle is our handle now
		if (GetProcessId(duplicated_handle) == target_pid)
		{
			//just a simple queryObject call to check if the original handle was a process handle, we need to use the duplicated handle otherwise it most likely won't work
			if (!IsProcessHandle(duplicated_handle, pfNtQueryObject))
			{
				CloseHandle(handle_to_current_handle_owner);
				CloseHandle(duplicated_handle);
				continue;
			}
			
			v_handles.push_back(
			    {
					.UniqueProcessId = shi->Handles[handle_index].UniqueProcessId,
					.HandleValue = handle_to_duplicate,
					.GrantedAccess = shi->Handles[handle_index].GrantedAccess
				}
			);

			CONSOLE_LOG_ARGS(false, "Handle Owner: ", shi->Handles[handle_index].UniqueProcessId)
			CONSOLE_LOG_ARGS(false, "Handle access: ", reinterpret_cast<void*>(shi->Handles[handle_index].GrantedAccess))
			CONSOLE_LOG("/**************************************************/")
		}

		//close our newly created handles
		CloseHandle(handle_to_current_handle_owner);
		CloseHandle(duplicated_handle);

		//we could break here and just stop which can save us thousands of iterations however having more handles available than just one is better since we won't know
		//if we will run into issues with that one handle and therefore if more are available we can simply check if the other one works with the injection if the first one fails 
	}

	return v_handles;
}

#pragma region SHELLCODE_SEGMENT_1
struct INJECTION_ARGUMENTS
{
	void* pfInject = nullptr;
	HANDLE hijacked_handle = nullptr;
	DWORD64 additional_flags = 0;
	HandleHijackerGlobal::HandleHijackerAdditionalArgs* pAdditionalArgs;
	HMODULE ownModule = nullptr;
	NTSTATUS(*pfLdrUnloadDll)(HANDLE) = nullptr;
	DWORD pid = 0;
	Injection_Method injection_method;
	bool is_x64 = true;
	DWORD exit_status = 6337;
	bool executed = false;
	wchar_t dllpath[MAX_PATH];
	wchar_t symbol_path[MAX_PATH];
	wchar_t exec_method[MAX_PATH];
};

//since I fucked up early in my code we need this to make it work
#pragma code_seg (push)
#pragma code_seg(".ISrc1")
static void InjectFunctionWrapperShellcode(INJECTION_ARGUMENTS* pArgs)
{
	pArgs->pAdditionalArgs->hijacked_handle = pArgs->hijacked_handle;
	pArgs->pAdditionalArgs->path = pArgs->symbol_path;

#ifdef _WIN64
	pArgs->exit_status = reinterpret_cast<bool(__fastcall*)(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)>(pArgs->pfInject)
	(pArgs->dllpath, pArgs->pid, pArgs->injection_method, pArgs->exec_method, pArgs->additional_flags, pArgs->is_x64);
#else
	pArgs->exit_status = reinterpret_cast<bool(__cdecl*)(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)>(pArgs->pfInject)
	(pArgs->dllpath, pArgs->pid, pArgs->injection_method, pArgs->exec_method, pArgs->additional_flags, pArgs->is_x64);
#endif

	pArgs->pfLdrUnloadDll(pArgs->ownModule);
	pArgs->executed = true;
}

static void dummy(){}
#pragma code_seg (pop)
#pragma endregion SHELLCODE_SEGMENT_1

std::wstring GetModuleFilePath()
{
	wchar_t own_dll_path[MAX_PATH];
	GetModuleFileNameW(GetModuleHandleW(OWN_MODULE_NAME), own_dll_path, sizeof(own_dll_path));
	return { own_dll_path };
}

std::uintptr_t GetModuleBaseEx(DWORD pid)
{
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	MODULEENTRY32W me32 {.dwSize = sizeof(MODULEENTRY32)};

	if (!Module32FirstW(snapshot_handle, &me32))
		return 0;

	do
	{
		if (!wcscmp(me32.szModule, OWN_MODULE_NAME))
			return reinterpret_cast<std::uintptr_t>(me32.modBaseAddr);
	}
	while (Module32NextW(snapshot_handle, &me32));

	CloseHandle(snapshot_handle);
	return 0;
}

static bool InjectShellcode(DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64, const TARGET_HANDLE_INFO handle_info, void* pfInject, Injection_Method injection_method, const wchar_t* dllpath_to_inject)
{
	//Handle to the owner of the current handle to our target
	DWORD handle_access_flags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
	HANDLE handle_owner = OpenProcess(handle_access_flags, false, handle_info.UniqueProcessId);

	if (!handle_owner)
		return false;

	DWORD64 function_size = reinterpret_cast<DWORD64>(dummy) - reinterpret_cast<DWORD64>(InjectFunctionWrapperShellcode);

	void* allocated_memory_code = VirtualAllocEx(handle_owner, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);

	if (!allocated_memory_code)
		return false;

	if(!WriteProcessMemory(handle_owner, allocated_memory_code, InjectFunctionWrapperShellcode, function_size, nullptr))
	{
		Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_code);
		CloseHandle(handle_owner);
		return false;
	}

	void* allocated_memory_buffer = VirtualAllocEx(handle_owner, nullptr, sizeof(INJECTION_ARGUMENTS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!allocated_memory_buffer)
		return false;

	/*
	* gets us the path on where our module/dll is
	* the function is using my OWN_MODULE_NAME macro and calls GetModuleFileNameW
	*/
	std::wstring dllpath = GetModuleFilePath();

	if (dllpath.empty())
		return false;

	//injecting myself into process that currently holds the handle to our initial target process
	bool ret_status = oCreateThread::Injection(dllpath.c_str(), handle_info.UniqueProcessId,
		Injection_Method::_LoadLibrary, L"NtCreateThreadEx",
		MI_THREAD_START_ADDRESS_SPOOF | MI_THREAD_HIDE_FROM_DEBUGGER, is_x64);

	if(!ret_status)
	{
		Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_code, allocated_memory_buffer);
		CloseHandle(handle_owner);
		return false;
	}

	//there are better solutions but it works well, im using a global struct which I can easily obtain the address from.
	HMODULE own_base_address = GetModuleHandleW(OWN_MODULE_NAME);
	std::uintptr_t fInject_offset = reinterpret_cast<std::uintptr_t>(pfInject) - reinterpret_cast<std::uintptr_t>(own_base_address);
	std::uintptr_t offset_to_Additional_Args_struct = reinterpret_cast<std::uintptr_t>(&HandleHijackerGlobal::AdditionalArgs) - reinterpret_cast<std::uintptr_t>(own_base_address);

	INJECTION_ARGUMENTS fArgs;

	//obv we need to change the flags to avoid recursion in the handle hijacker and letting my own dll know that we are inside the process holding the handle to the target so we don't close any handles.
	DWORD64 additional_flags_adapted = additional_flags;
	additional_flags_adapted &= ~MI_HIJACK_HANDLE;
	additional_flags_adapted |= INSIDE_HIJACKED_HANDLE_PROCESS;

	/*
	 * GetModuleBaseEx returns the base address of my loaded module/dll as an unsigned integer
	 * The function has a macro with our module name, don't let that confuse you.
	 */

	fArgs.additional_flags = additional_flags_adapted;
	fArgs.is_x64		   = is_x64;
	fArgs.hijacked_handle  = handle_info.HandleValue;
	fArgs.pfInject		   = reinterpret_cast<void*>(fInject_offset + GetModuleBaseEx(handle_info.UniqueProcessId)); 
	fArgs.pid			   = pid;
	fArgs.pAdditionalArgs  = reinterpret_cast<HandleHijackerGlobal::HandleHijackerAdditionalArgs*>(offset_to_Additional_Args_struct + GetModuleBaseEx(handle_info.UniqueProcessId));
	fArgs.injection_method = injection_method;
	fArgs.ownModule		   = reinterpret_cast<HMODULE>(GetModuleBaseEx(handle_info.UniqueProcessId));
	fArgs.pfLdrUnloadDll   = reinterpret_cast<decltype(fArgs.pfLdrUnloadDll)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrUnloadDll"));

	std::filesystem::path path_to_symbols;
	if(is_x64)
		path_to_symbols = std::filesystem::current_path() / L"Symbolx64";
	else
		path_to_symbols = std::filesystem::current_path() / L"Symbolx86";

	memcpy_s(fArgs.symbol_path, sizeof(fArgs.symbol_path), path_to_symbols.c_str(), std::wcslen(path_to_symbols.c_str()) * sizeof(wchar_t) + 2);

	memcpy_s(fArgs.exec_method, sizeof(fArgs.exec_method), exec_method, std::wcslen(exec_method) * sizeof(wchar_t) + 2);

	memcpy_s(fArgs.dllpath, sizeof(fArgs.dllpath), dllpath_to_inject, std::wcslen(dllpath_to_inject) * sizeof(wchar_t) + 2);

	if (!WriteProcessMemory(handle_owner, allocated_memory_buffer, &fArgs, sizeof(INJECTION_ARGUMENTS), nullptr))
	{
		Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_code, allocated_memory_buffer);
		CloseHandle(handle_owner);
		return false;
	}

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	const NtCreateThreadEx pfNtCreateThreadEx = reinterpret_cast<NtCreateThreadEx>(GetProcAddress(ntdll, "NtCreateThreadEx"));

	HANDLE thread_handle = nullptr;

	//creating the thread in the target to execute our shellcode which then calls the function pointer which called this handler. Basically resuming the execution but now in another process which has access to the handle table we found
	//also this is the reason why my functions need to follow a certain signature
	(void)pfNtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS,
					   nullptr, handle_owner,
					   nullptr, allocated_memory_buffer,
					   THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0,
					   0, 0,
					   nullptr);
	if(!thread_handle)
	{
		Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_code, allocated_memory_buffer);
		CloseHandle(handle_owner);
		return false;
	}

	CONTEXT thread_ctx {.ContextFlags = CONTEXT_ALL};
	GetThreadContext(thread_handle, &thread_ctx);

#ifdef _WIN64
	thread_ctx.Rcx = reinterpret_cast<DWORD64>(allocated_memory_code);
#else
	thread_ctx.Eax = reinterpret_cast<DWORD>(allocated_memory_code);
#endif

	if(!SetThreadContext(thread_handle, &thread_ctx))
	{
		Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_code, allocated_memory_buffer);
		CloseHandle(handle_owner);
		return false;
	}
	
	ResumeThread(thread_handle);
	WaitForSingleObject(thread_handle, INFINITE);
	CloseHandle(thread_handle);

	DWORD time_passed = 0;
	DWORD shellcode_return_value = 6337;
	bool executed = false;

	do
	{
		if (!ReadProcessMemory(handle_owner, static_cast<BYTE*>(allocated_memory_buffer) + offsetof(INJECTION_ARGUMENTS, exit_status), &shellcode_return_value, sizeof(DWORD), nullptr) || time_passed >= 30)
		{
			Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_buffer, allocated_memory_code);
			CloseHandle(handle_owner);
	
			return false;
		}

		if (!ReadProcessMemory(handle_owner, static_cast<BYTE*>(allocated_memory_buffer) + offsetof(INJECTION_ARGUMENTS, executed), &executed, sizeof(bool), nullptr) || time_passed >= 30)
		{
			Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_buffer, allocated_memory_code);
			CloseHandle(handle_owner);

			return false;
		}
	
		++time_passed;
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	} while (shellcode_return_value == 6337 || !executed);

	Utility::FreeAllocatedMemoryEx(handle_owner, "", allocated_memory_buffer, allocated_memory_code);
	CloseHandle(handle_owner);

	return ((shellcode_return_value != 6337) ? shellcode_return_value : false);
}

bool HandleHijacker(DWORD target_pid, DWORD desired_handle_access_flags, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64, void* pfInject, Injection_Method injection_method, const wchar_t* dllpath_to_inject)
{
	//multiple ways of doing this
	
	/*  1
	 *	Injecting our Injector dll inside the handle owner process 
	 */

	/*	2
	 *	Rewriting everything and injecting one function which does all of the stuff our initial injection functions would do, and execute this inside the handle owner process 
	 */

	/*	3
	 *	Make a new Handle Hijack dll and inject inside the handle owner process 
	 */

	/*	4
	 *	IPC and use everything as normal however we would need to change some working code and make it work with and without IPC
	 */

	//thinking about the options I have now I would go with 1 this one should be the fastest one to implement, IPC would also be an option however it's overkill for an injector.

	HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");

	if(additional_flags & MI_SYSTEM_PROCESS_ONLY)
	{
		//so we can access processes that have the Privilege level of System Integrity Level since admin Privilege
		//only gives us access to High Integrity level afaik however we can simply get SIL by doing this
		BOOLEAN previous_priv_b;
		reinterpret_cast<RtlAdjustPrivilege>(GetProcAddress(ntdll_module, "RtlAdjustPrivilege"))
		(/*SeDebugPrivilege = 20 ->*/ 20, true, false, &previous_priv_b);
	}

	std::vector<TARGET_HANDLE_INFO> v_target_handle_info = FindHandlesToHijack(target_pid, desired_handle_access_flags);

	NtQueryInformationProcess pfNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(ntdll_module, "NtQueryInformationProcess"));

	bool exit_code = false;
	for (const TARGET_HANDLE_INFO handle_info : v_target_handle_info)
	{
		//There are cases where a game uses some sort of bootstrap or something else best example is Unreal Engine before launching the actual game usually the bootstrap is executed to
		//do some checks on the system or whatever, however since this one is not the actual game exe my hijacker will hijack the bootstrap of the game and find a full access handle to it
		//since I don't want this behaviour I wrote this
		if(additional_flags & MI_SYSTEM_PROCESS_ONLY)
		{
			PROCESS_BASIC_INFORMATION process_basic_info = {};
			HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, handle_info.UniqueProcessId);

			if (process_handle)
			{
				//ProcessIdToSessionId(handle_info.UniqueProcessId, &SessionID) is also a valid option im basically doing the same, check it in ida.
				//why did I rewrite what ProcessIdToSessionId does?? BECAUSE I learned about that function after I wrote this lol

				pfNtQueryInformationProcess(process_handle, PROCESSINFOCLASS::ProcessBasicInformation,
					&process_basic_info, sizeof(process_basic_info),
					nullptr);
				ULONG SessionID = 99;
				(void)ReadProcessMemory(process_handle, &process_basic_info.PebBaseAddress->SessionId, &SessionID, sizeof(ULONG), nullptr);

				CloseHandle(process_handle);

				//essentially if the process is not a system process
				if (SessionID != 0)
					continue;
			}
		}

		if (exit_code = InjectShellcode(target_pid, exec_method, additional_flags, is_x64, handle_info, pfInject, injection_method, dllpath_to_inject))
			break;
	}

	return exit_code;
}