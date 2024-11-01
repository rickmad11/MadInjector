#include "pch.h"

#ifdef _WIN64

#include <functional>

#include "ManualMapper/ManualMapper.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "HandleHijacker/HandleHijacker.hpp"

namespace oManualMapper
{
	//Inside ManualMap.cpp
	extern bool ManualMapExecutionStub(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, const wchar_t* const exec_method, DWORD64 additional_flags, DWORD pid);
	extern void AdjustHandleFlags(DWORD& access_flags, const wchar_t* exec_method);
}

struct MODULE_UNLOAD_DATA
{
	//bcs my shit was not made to be generic (at least not all of my exec methods, I think the thread hijacker is the only one without an own check)
	//usually the exec function should have their own check if executed in the shellcode itself 
	//but I dont and all I want rn is to finish this shit 
	char pad[0x64] {};
	bool execution_finished = false;
	void* dll_base = nullptr;
	void* tls_callbacks = nullptr;
	void* dependencies[200] = {};

	NTSTATUS(*pfLdrUnloadDll)(HANDLE) = nullptr;
	decltype(RtlDeleteFunctionTable)* pfRtlDeleteFunctionTable = nullptr;
	DWORD AddressOfEntryPoint = 0;
	DWORD function_table = 0;
	bool seh_enabled = false;
};

#pragma code_seg (push)
#pragma code_seg(".mmm")
#pragma optimize("", off)

//NOTE: there are still some modules that are not being unloaded I don't fucking know why and I will not bother looking into it if anyone know why it happens please tell me
//I should leave a screenshot somewhere on github how before and after looks like 
static void __stdcall UnloadDll(MODULE_UNLOAD_DATA* mi)
{
	if (!mi || !mi->dll_base)
		return;

	BYTE* base = reinterpret_cast<BYTE*>(mi->dll_base);

	if(mi->tls_callbacks)
	{
		PIMAGE_TLS_CALLBACK* callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(mi->tls_callbacks);
		for (; callback && *callback; ++callback)
			(*callback)(mi->dll_base, DLL_PROCESS_DETACH, nullptr);
	}

	typedef BOOL(WINAPI* DllMain)(
		HINSTANCE hinstDLL,
		DWORD fdwReason,
		LPVOID lpvReserved);

	(void)reinterpret_cast<DllMain>(mi->AddressOfEntryPoint + base) (reinterpret_cast<HINSTANCE>(mi->dll_base), DLL_PROCESS_DETACH, nullptr);

	//Removing Function Table for SEH
	if(mi->seh_enabled)
		mi->pfRtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(mi->AddressOfEntryPoint + base));

	//TODO LdrpCleanupThreadTlsData??

	//Unload all dependencies

	PPEB pPEB = reinterpret_cast<PPEB>(__readgsqword(0x60));

	void* pMemoryOrderListHead = &pPEB->Ldr->InMemoryOrderModuleList;

	for (size_t i = 0; i < (sizeof(mi->dependencies) / sizeof(void*)); i++)
	{
		//if we encounter the first nullptr we should be done with all of them
		if (!mi->dependencies[i])
			break;

		//There are better ways of doing this for instance caching all dlls with base addr and their reference count externally so basically only loop once with rpm and
		//only save the dlls that are to be unloaded, im currently looping through the ENTIRE list every single fucking iteration which is terrible BUT it saves me time, so I can finally
		//complete this project lol
		for (PLIST_ENTRY curr = pPEB->Ldr->InMemoryOrderModuleList.Flink; curr != pMemoryOrderListHead; curr = curr->Flink )
		{
			PLDR_DATA_TABLE_ENTRY pLdr = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if(pLdr->DllBase == mi->dependencies[i] && pLdr->ReferenceCount)
			{
				//pLdr->ReferenceCount = 1 <- yeah I think that might also work lol

				//-1 bcs we unload again in our outer loop
				//yes we should be fine with unsigned integer overflow since I checked if ReferenceCount is true which is the same as ReferenceCount != 0
				for (size_t j = 0; j < pLdr->ReferenceCount - 1; j++)
					mi->pfLdrUnloadDll(mi->dependencies[i]);

				break;
			}
		}

		mi->pfLdrUnloadDll(mi->dependencies[i]);
	}

	mi->execution_finished = true;
}

static void Dummy() { std::cout << "just in case my compiler does shit to me again"; }

#pragma optimize("", on)
#pragma code_seg (pop)

//This is the function our manual mapper will invoke before we inject/load dependencies of  our mapped dll
void SaveCurrentModulesToFile(DWORD pid)
{
	HANDLE module_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!module_snapshot)
	{
		CONSOLE_LOG_ERROR("Saving Modules for Unload Process failed!")
		return;
	}

	MODULEENTRY32W me = { .dwSize = sizeof(MODULEENTRY32W) };

	if (!Module32FirstW(module_snapshot, &me))
		return;

	std::wstring root_path = GetModuleFilePath();

	size_t pos = root_path.rfind('\\');
	if (pos == std::wstring::npos)
	{
		CONSOLE_LOG_ERROR("Saving Modules for Unload Process failed!")
		return;
	}

	root_path.erase(root_path.cbegin() + pos, root_path.cend());

	std::filesystem::path fixed_path = root_path;
	std::wofstream dll_info_file{ (fixed_path / "manual_mapped_dll_info.txt"), std::ios::app };

	if (!dll_info_file.is_open())
	{
		CONSOLE_LOG_ERROR("Saving Modules for Unload Process failed!")
		return;
	}

	dll_info_file << L"Dependencies:" << '\n';

	//we don't care about the first one it is always the base executable
	while (Module32NextW(module_snapshot, &me))
		dll_info_file << me.szModule << '\n';

	dll_info_file.close();
}

static std::vector<std::pair<std::wstring, void*>> GetCurrentModulesEx(DWORD pid)
{
	HANDLE module_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!module_snapshot)
		return {};

	MODULEENTRY32W me = { .dwSize = sizeof(MODULEENTRY32W) };

	if (!Module32FirstW(module_snapshot, &me))
		return {};

	std::vector<std::pair<std::wstring, void*>> modules {}; 
	modules.reserve(100);

	//we don't care about the first one it is always the base executable
	while (Module32NextW(module_snapshot, &me))
		modules.emplace_back(me.szModule, me.modBaseAddr);

	return modules;
}

/*
 * The idea here is to make a snapshot of all loaded modules before we map our dll with all of its module names.
 * These are then saved on disk in a txt file named manual_mapped_dll_info.txt then we make another snapshot when somebody clicks the button Unload Mapped Dll
 * which then compares the old and the new snapshot, every module that was not part of the first snapshot is considered to be part of the loaded dependency of the mapped dll.
 * This has some advantages such as quick and easy code and no need to keep track of dependencies in our manual mapper however downside is the process could load a module
 * (after we mapped) which has nothing to do with our shit, and therefore it would be unloaded as well which might cause crashes/issues BUT it's quite rare that a process loads
 * another module/s after initialization so my way of doing this should work in 99% of cases except im totally wrong here, but I am 99% sure that most processes won't do that.
 */

/*
 * NOTE: This will only work with dlls that are kinda aware that they are being manual mapped if you know what I mean, what im saying is it needs to exit its thread (if it created one)
 * so that I can unmap the memory otherwise the thread will access freed memory which obv is a crash. If there is no thread created make sure every hooks or whatever are cleaned up and no one is
 * accessing the dlls memory anymore. A simple solution is having a bool which checks if DllMain got called with DLL_PROCESS_DETACH and then do the cleanup operations.
 * If you can make your dll unmap itself with a custom virtualfree wrapped in assembly idk never did this but I have heard ppl do it? in that case you won't need my unload code  
 */

//these void* dummies are there so it works with the handle hijacker
//also using string_view will cause the handle hijacker to shit itself 
bool UnloadMappedDll(void*, DWORD pid, void*, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
{
	DWORD access_flags = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
	HANDLE process_handle = nullptr;

	oManualMapper::AdjustHandleFlags(access_flags, exec_method);

	if (additional_flags & MI_HIJACK_HANDLE)
		return HandleHijacker(pid, access_flags, exec_method, additional_flags, is_x64, UnloadMappedDll, {}, L"nullptr");

	bool is_inside_hijacked_process = additional_flags & INSIDE_HIJACKED_HANDLE_PROCESS;
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

	std::wstring root_path = GetModuleFilePath();

	size_t pos = root_path.rfind('\\');
	if (pos == std::wstring::npos)
	{
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}

	root_path.erase(root_path.cbegin() + pos, root_path.cend());

	std::filesystem::path fixed_path = root_path;
	std::wifstream dll_info_file{ (fixed_path / "manual_mapped_dll_info.txt") };

	if (!dll_info_file.is_open())
	{
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}

	std::vector<DWORD64> mapped_dll_info {};
	mapped_dll_info.reserve(4);

	std::wstring line {};
	while (std::getline(dll_info_file, line))
	{
		//Mapped Dll Base: 0
		//AddressOfCallBacks: 1
		//AddressOfEntryPoint: 2
		//Runtime Function Table 3
		//SEH 4
		//Image Size: 5

		if(line.contains(L"Image Size"))
		{
			std::getline(dll_info_file, line);
			mapped_dll_info.push_back(std::stoul(line.data()));
			break;
		}

		if(line.contains(L"AddressOfEntryPoint"))
		{
			std::getline(dll_info_file, line);
			mapped_dll_info.push_back(std::stoul(line.data()));
			continue;
		}

		if(line.contains(L"Runtime Function Table"))
		{
			std::getline(dll_info_file, line);
			mapped_dll_info.push_back(std::stoul(line.data()));
			continue;
		}

		if (line.contains(L"SEH"))
		{
			std::getline(dll_info_file, line);
			mapped_dll_info.push_back(std::stol(line.data()));
			continue;
		}

		if(line.contains(':'))
		{
			std::getline(dll_info_file, line);
			mapped_dll_info.push_back(std::wcstoull(line.data(), nullptr, 16));
		}
	}

	if (mapped_dll_info.size() < 6)
	{
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}

	MODULE_UNLOAD_DATA mud
	{
		.dll_base					= reinterpret_cast<void*>(mapped_dll_info.at(0)),
		.tls_callbacks				= reinterpret_cast<void*>(mapped_dll_info.at(1)),
		.pfLdrUnloadDll				= reinterpret_cast<decltype(mud.pfLdrUnloadDll)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrUnloadDll")),
		.pfRtlDeleteFunctionTable	= RtlDeleteFunctionTable,
		.AddressOfEntryPoint		= static_cast<DWORD>(mapped_dll_info.at(2)),
		.function_table				= static_cast<DWORD>(mapped_dll_info.at(3)),
		.seh_enabled				= static_cast<bool>(mapped_dll_info.at(4)),
	};

	for (size_t count = 0, index = 0; std::pair<std::wstring, void*> const& curr_module : GetCurrentModulesEx(pid))
	{
		if (count >= 200)
			break;

		std::getline(dll_info_file, line);

		//only testing if my txt file contains any module names since maybe it failed earlier (like I said error handling in this project is just ass)
		if (!count && line != L"Dependencies:")
		{
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
			return false;
		}

		//not gonna waste another string comparison lol, the last check made sure line is == Dependencies therefore we just need to go to the other line just once at index 0
		if(!count)
			std::getline(dll_info_file, line);

		if(line == curr_module.first)
		{
			count++;
			continue;
		}

		if(curr_module.second)
		{
			mud.dependencies[index] = curr_module.second;
			++index;
		}

		count++;
	}

	size_t function_size = reinterpret_cast<DWORD64>(Dummy) - reinterpret_cast<DWORD64>(UnloadDll);
	void* allocated_functionUnloadDll = VirtualAllocEx(process_handle, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE);

	if(!allocated_functionUnloadDll)
	{
		CONSOLE_LOG_ERROR("Allocation for function failed")
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}

	void* allocated_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(MODULE_UNLOAD_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if(!allocated_buffer)
	{
		Utility::FreeAllocatedMemoryEx(process_handle, "Allocation for Buffer failed", allocated_functionUnloadDll);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}

	if(!WriteProcessMemory(process_handle, allocated_functionUnloadDll, UnloadDll, function_size, nullptr))
	{
		Utility::FreeAllocatedMemoryEx(process_handle, "Writing function failed", allocated_functionUnloadDll, allocated_buffer);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}

	if (!WriteProcessMemory(process_handle, allocated_buffer, &mud, sizeof(MODULE_UNLOAD_DATA), nullptr))
	{
		Utility::FreeAllocatedMemoryEx(process_handle, "Writing Buffer failed", allocated_functionUnloadDll, allocated_buffer);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}

	if(!oManualMapper::ManualMapExecutionStub(process_handle, allocated_functionUnloadDll, allocated_buffer, exec_method, additional_flags, pid))
	{
		Utility::FreeAllocatedMemoryEx(process_handle, "Execution failed", allocated_functionUnloadDll, allocated_buffer);
		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;
		return false;
	}
	
	DWORD time_passed = 0;
	bool is_executed = false;
	do
	{
		if (time_passed >= 15)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, {}, allocated_functionUnloadDll, allocated_buffer);
	
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
	
			return false;
		}
	
		ReadProcessMemory(process_handle, static_cast<BYTE*>(allocated_buffer) + offsetof(oManualMapper::MANUAL_MAP_BUFFER, execution_finished), &is_executed, sizeof(bool), nullptr);
	
		++time_passed;
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	} while (!is_executed);
	
	Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_functionUnloadDll, allocated_buffer);

	if(is_executed)
	{
		//TODO maybe zero memory after free vf should be enough tho dunno
		size_t image_size = mapped_dll_info.at(5);
		if (!VirtualFreeEx(process_handle, mud.dll_base, 0, MEM_RELEASE))
		{
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;
		
			CONSOLE_LOG_ERROR("Freeing Mapped dll Memory failed")
			return false;
		}
	}

	if (!is_inside_hijacked_process)
		process_handle ? CloseHandle(process_handle) : NULL;

	return is_executed;
}

#endif //_WIN64