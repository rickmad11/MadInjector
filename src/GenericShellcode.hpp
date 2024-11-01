#pragma once

#include "MadInjector.hpp"
#include "ExecutionMethods.hpp"

struct THREAD_BUFFER
{
	PWCHAR PathToFile = nullptr;
	WCHAR dllpath[MAX_PATH]{};

	Injection_Method injection_method {};

	ULONG Flags = NULL;
	HANDLE ModuleHandle = INVALID_HANDLE_VALUE;
	PVOID ModuleBase = nullptr;

	DWORD64 additional_flags = 0;

#ifdef _WIN64
	//default init all of these structs otherwise it's UB and might lead to issues trust me
	LDRP_LOAD_CONTEXT_FLAGS ctf{};
	PLDR_DATA_TABLE_ENTRY pData_Table = nullptr;
	LDRP_PATH_SEARCH_CONTEXT sct{};

	UNICODE_STRING ModuleFileName{};
	LDRP_UNICODE_STRING_BUNDLE PreprocessedDllName{};

	NTSTATUS status = S_OK;

	RtlInitUnicodeString pfRtlInitUnicodeString = nullptr;
#else
	LDRP_LOAD_CONTEXT_FLAGS_32 ctf{};
	LDR_DATA_TABLE_ENTRY_32* pData_Table = nullptr;
	LDRP_PATH_SEARCH_CONTEXT_32 sct{};

	UNICODE_STRING_32 ModuleFileName{};
	LDRP_UNICODE_STRING_BUNDLE PreprocessedDllName{};

	NTSTATUS status = S_OK;

	RtlInitUnicodeString pfRtlInitUnicodeString = nullptr;
#endif

	LdrpPreprocessDllName pfLdrpPreprocessDllName = nullptr;

	LdrpLoadDllInternal pfLdrpLoadDllInternal = nullptr;
	LdrpLoadDll pfLdrpLoadDll = nullptr;
	LdrLoadDll pfLdrLoadDll = nullptr;
	decltype(LoadLibraryW)* pfLoadLibrary = nullptr;

	bool injection_status = false;
	bool is_executed = false;
};

#pragma code_seg (push)
#pragma code_seg(".MIGI")

inline void __stdcall Shellcode(THREAD_BUFFER* buffer)
{
	if (!buffer)
		return;

	if (buffer->injection_status)
		return;

	buffer->is_executed = true;

	if (buffer->injection_method == Injection_Method::_LoadLibrary && buffer->pfLoadLibrary)
	{
		buffer->injection_status = true; //very important it needs to be here not below it otherwise you will encounter crashes

		buffer->ModuleBase = buffer->pfLoadLibrary(buffer->dllpath);
	}

	if (!buffer->pfRtlInitUnicodeString)
		return;

	if (buffer->injection_method == Injection_Method::_LdrLoadDll && buffer->pfLdrLoadDll)
	{
		buffer->injection_status = true; //very important it needs to be here not below it otherwise you will encounter crashes

		buffer->pfRtlInitUnicodeString(&buffer->ModuleFileName, buffer->dllpath);
		buffer->status = buffer->pfLdrLoadDll(buffer->PathToFile, buffer->Flags, &buffer->ModuleFileName, &buffer->ModuleHandle);
		buffer->ModuleBase = buffer->ModuleHandle;
	}

	if (buffer->injection_method == Injection_Method::_LdrpLoadDll && buffer->pfLdrpLoadDll)
	{
		buffer->injection_status = true; //very important it needs to be here not below it otherwise you will encounter crashes

		buffer->pfRtlInitUnicodeString(&buffer->ModuleFileName, buffer->dllpath);
		buffer->status = buffer->pfLdrpLoadDll(&buffer->ModuleFileName, &buffer->sct, buffer->ctf, &buffer->pData_Table);
		buffer->ModuleBase = reinterpret_cast<PVOID>(buffer->pData_Table->DllBase);
	}

	if (!buffer->pfLdrpPreprocessDllName)
		return;

	if (buffer->injection_method == Injection_Method::_LdrpLoadDllInternal && buffer->pfLdrpLoadDllInternal)
	{
		buffer->injection_status = true; //very important it needs to be here not below it otherwise you will encounter crashes

		buffer->pfRtlInitUnicodeString(&buffer->ModuleFileName, buffer->dllpath);
		buffer->PreprocessedDllName.String.Buffer = buffer->PreprocessedDllName.StaticBuffer;
		buffer->status = buffer->pfLdrpPreprocessDllName(&buffer->ModuleFileName, &buffer->PreprocessedDllName, buffer->pData_Table, &buffer->ctf);
		buffer->pfLdrpLoadDllInternal(&buffer->PreprocessedDllName.String, &buffer->sct, buffer->ctf, 4, nullptr, nullptr, &buffer->pData_Table, &buffer->status, 0);
		buffer->ModuleBase = reinterpret_cast<PVOID>(buffer->pData_Table->DllBase);
	}

#ifdef _WIN64
	//btw im pretty sure most of you know this but this won't make your module really hidden NtQueryVirtualMemory uses the vad tree so this is kinda useless but then again
	//why not have it as an option wasn't that much code 
	if(buffer->additional_flags & MI_UNLINK_MODULE_INTERNAL)
	{
		//might not work on x86 since idk if I have the correct x86 structures. (injector is x64 focused anyway)
		//I just decided to remove this entire option for x86 
		PEB* pPeb = NtCurrentTeb()->ProcessEnvironmentBlock;

		PPEB_LDR_DATA p_ldr_data = pPeb->Ldr;

		PLIST_ENTRY entries[3] = { &p_ldr_data->InLoadOrderModuleList, &p_ldr_data->InMemoryOrderModuleList, &p_ldr_data->InInitializationOrderModuleList };

		for (size_t i = 0; i < 3; i++)
		{
			for (PLIST_ENTRY curr = entries[i]->Flink; curr != entries[i]; curr = curr->Flink)
			{
				PLDR_DATA_TABLE_ENTRY p_ldr_data_table = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(reinterpret_cast<BYTE*>(curr) - (i * sizeof(LIST_ENTRY)));

				if (p_ldr_data_table->DllBase == buffer->ModuleBase)
				{
					curr->Flink->Blink = curr->Blink;
					curr->Blink->Flink = curr->Flink;

					p_ldr_data_table->DllBase = nullptr;
					p_ldr_data_table->BaseDllName = {};
					p_ldr_data_table->FullDllName = {};
					p_ldr_data_table->ParentDllBase = nullptr;

					if (i == 0)
					{
						p_ldr_data_table->HashLinks.Flink->Blink = p_ldr_data_table->HashLinks.Blink;
						p_ldr_data_table->HashLinks.Blink->Flink = p_ldr_data_table->HashLinks.Flink;
					}
				}
			}
		}
	}
#endif
}

inline void __stdcall Dummy() { std::cout << "just in case my compiler doesn't fuck me over again"; }

#pragma code_seg (pop)
