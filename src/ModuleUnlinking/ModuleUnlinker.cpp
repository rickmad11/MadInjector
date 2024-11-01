#include "pch.h"

#ifdef _WIN64

#include "InternalFunctions.h"
#include "MadInjector.hpp"

//since my injector is more like of a reference I had to make A LOT of bad coding decisions
//however I still want to add a Module Unlinker and in order to do this without modifying 10 source files im going to do it fully externally without any internal help
//This one supports any dll even if not injected with my injector all I need is the dllpath and the dll has to be loaded by the windows loader kinda makes sense right xD

//error checking sucks here if some read or write fails I could still return true since I return based if I found the module not if I unlinked it reason for it LESS CODE xD
//NO console output supported on this call
//also note this will break dlls that dont expect to be unlinked from the peb for instance calling freelibrary...
//these void* dummies are there so it works with the handle hijacker
bool UnlinkModule(const wchar_t* dllpath, DWORD pid, void* , void*, DWORD64 additional_flags, bool is_x64)
{
	std::wstring dll_name{ dllpath };
	size_t pos = dll_name.rfind('/');

	if (pos == std::wstring::npos)
		return false;

	dll_name.erase(dll_name.cbegin(), dll_name.cbegin() + pos + 1);

	DWORD access_flags = PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
	HANDLE process_handle = nullptr;

	if (additional_flags & MI_HIJACK_HANDLE)
		return HandleHijacker(pid, access_flags, L"nullptr", additional_flags, is_x64, UnlinkModule, {/*no need for this*/}, dllpath);

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

	HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");
	NtQueryInformationProcess pfNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(ntdll_module, "NtQueryInformationProcess"));

	PROCESS_BASIC_INFORMATION process_basic_info = {};
	pfNtQueryInformationProcess(process_handle, PROCESSINFOCLASS::ProcessBasicInformation,
		&process_basic_info, sizeof(process_basic_info),
		nullptr);

	PPEB_LDR_DATA pLdr = nullptr;
	(void)ReadProcessMemory(process_handle, &process_basic_info.PebBaseAddress->Ldr, &pLdr, sizeof(void*), nullptr);

	void* data_table_entry_heads[3] {};
	for (size_t index = 0; index < 3; index++)
		//the idea here is to reduce my code a bit and basically work our way from InLoadOrderModuleList down to the InInitializationOrderModuleList
		data_table_entry_heads[index] = reinterpret_cast<BYTE*>(&pLdr->InLoadOrderModuleList) + sizeof(LIST_ENTRY) * index;

	bool is_module_found = false;

	for (size_t index = 0; index < 3; index++)
	{
		void* init = nullptr;
		(void)ReadProcessMemory(process_handle, &reinterpret_cast<PLIST_ENTRY>(data_table_entry_heads[index])->Flink, &init, sizeof(void*), nullptr);

		for (PLIST_ENTRY curr = reinterpret_cast<PLIST_ENTRY>(init); curr != data_table_entry_heads[index]; (void)ReadProcessMemory(process_handle, &curr->Flink, &curr, sizeof(void*), nullptr))
		{
			//don't let the - confuse you we used + before since we started from top to bottom now we need to calculate the base of the structure which means we need to subtract 
			PLDR_DATA_TABLE_ENTRY pLdrEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(reinterpret_cast<BYTE*>(curr) - sizeof(LIST_ENTRY) * index);

			UNICODE_STRING BaseDllName{};
			(void)ReadProcessMemory(process_handle, &pLdrEntry->BaseDllName, &BaseDllName, sizeof(UNICODE_STRING), nullptr);

			//we could also make an array with the correct size but that would require allocations which is slow
			wchar_t found_dll_name[MAX_PATH];
			(void)ReadProcessMemory(process_handle, BaseDllName.Buffer, found_dll_name, BaseDllName.Length + sizeof(wchar_t), nullptr);

			if (!wcscmp(dll_name.c_str(), found_dll_name)) {
				is_module_found = true;

				LIST_ENTRY list{};
				(void)ReadProcessMemory(process_handle, curr, &list, sizeof(LIST_ENTRY), nullptr);

				(void)WriteProcessMemory(process_handle, &list.Flink->Blink, &list.Blink, sizeof(void*), nullptr);
				//curr->Flink->Blink = curr->Blink; <- This is what we did

				(void)WriteProcessMemory(process_handle, &list.Blink->Flink, &list.Flink, sizeof(void*), nullptr);
				//curr->Blink->Flink = curr->Flink;  <- This is what we did

				//This is for the HashLinks list the very last list we have to clear. Since we only need to walk it once we do it only on index 0 
				if(!index)
				{
					LIST_ENTRY hashlinks{};
					(void)ReadProcessMemory(process_handle, &pLdrEntry->HashLinks, &hashlinks, sizeof(LIST_ENTRY), nullptr);

					WriteProcessMemory(process_handle, &hashlinks.Flink->Blink, hashlinks.Blink, sizeof(void*), nullptr);
					//pLdrEntry->HashLinks.Flink->Blink = curr->Blink; <- This is what we did

					WriteProcessMemory(process_handle, &hashlinks.Blink->Flink, hashlinks.Flink, sizeof(void*), nullptr);
					//pLdrEntry->HashLinks.Blink->Flink = curr->Flink; <- This is what we did
				}
			}
		}
	}

	return is_module_found;
}

#endif //_WIN64