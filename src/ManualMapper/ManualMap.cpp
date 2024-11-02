#include "pch.h"

#ifdef _WIN64

#include <functional>

#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "ManualMapper.hpp"
#include "HandleHijacker/HandleHijacker.hpp"

//Can be found in UnloadMappedDll.cpp
extern void SaveCurrentModulesToFile(DWORD pid);

namespace oManualMapper
{
#pragma code_seg (push)
#pragma code_seg(".mMx")
#pragma optimize("", off) //never had issues before now I do lol well I guess I will stick with this solution for now

	__declspec(safebuffers) static void __stdcall ManualMapShellcode(MANUAL_MAP_BUFFER* buffer)
	{
		if (!buffer || !buffer->allocated_dll || !buffer->pfLdrpHandleTlsData ||
			!buffer->pfRtlAddFunctionTable || !buffer->pfLdrpLoadDll)
			return;

		BYTE* const allocated_dll = reinterpret_cast<BYTE*>(buffer->allocated_dll);

		PIMAGE_NT_HEADERS p_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(allocated_dll + buffer->e_lfanew);
		PIMAGE_OPTIONAL_HEADER p_optional_header = &p_nt_header->OptionalHeader;

		//Step 1 handle relocations if buffer->needs_reloc_fix is true

		PIMAGE_DATA_DIRECTORY p_image_reloc_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if(p_image_reloc_dir->Size && buffer->needs_reloc_fix)
		{
			PIMAGE_BASE_RELOCATION p_base_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(p_image_reloc_dir->VirtualAddress + allocated_dll);

			const std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(allocated_dll - p_optional_header->ImageBase);

			void* reloc_dir_end = reinterpret_cast<void*>(reinterpret_cast<DWORD64>(p_base_reloc) + p_image_reloc_dir->Size);

			for (PIMAGE_BASE_RELOCATION curr = p_base_reloc; curr && p_base_reloc < reloc_dir_end && curr->SizeOfBlock; curr = reinterpret_cast<PIMAGE_BASE_RELOCATION>(curr->SizeOfBlock + reinterpret_cast<BYTE*>(curr)))
			{
				if(curr->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
					continue;

				//SizeOfBlock is in bytes and also includes the very first two DWORD in the structure but we only want the relocation offsets which is a WORD array
				size_t reloc_amount = (curr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* reloc_offsets = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(&curr->SizeOfBlock) + sizeof(DWORD)); //base of reloc + sizeof(DWORD) *2 or sizeof(void*) or reinterpret_cast<WORD*>(curr + 1)...

				for (size_t i = 0; i < reloc_amount; i++)
				{
					//yeah I know a switch would be better but guess what I made an if chain

					//we want the type and the type of relocation is at the higher 4 bits 12-16 we need to use bit shift since IMAGE_REL_BASED_HIGHLOW is 3 which is 0011
					if ((reloc_offsets[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
					{
						//the reason we do (reloc_offsets[i] & 0xFFF) is because the offset is at bit 0-11 or 1 - 12 which we get with 0xFFF -> 0000 1111 1111 1111 you see it now?
						std::uintptr_t* reloc = reinterpret_cast<std::uintptr_t*>(allocated_dll + (reloc_offsets[i] & 0xFFF) + curr->VirtualAddress);
						*reloc += delta;
					}

					if ((reloc_offsets[i] >> 12) == IMAGE_REL_BASED_DIR64)
					{
						std::uintptr_t* reloc = reinterpret_cast<std::uintptr_t*>(allocated_dll + (reloc_offsets[i] & 0xFFF) + curr->VirtualAddress);
						*reloc += delta;
					}
					//IMAGE_REL_BASED_LOW -> x86
					if ((reloc_offsets[i] >> 12) == IMAGE_REL_BASED_LOW)
					{
						WORD* reloc = reinterpret_cast<WORD*>(allocated_dll + (reloc_offsets[i] & 0xFFF) + curr->VirtualAddress);
						*reloc += delta & 0xFFFF;
					}
					//IMAGE_REL_BASED_HIGH -> x86
					if ((reloc_offsets[i] >> 12) == IMAGE_REL_BASED_HIGH)
					{
						WORD* reloc = reinterpret_cast<WORD*>(allocated_dll + (reloc_offsets[i] & 0xFFF) + curr->VirtualAddress);
						*reloc += delta >> 16;
					}

				}
			}
			//or p_optional_header->ImageBase = allocated_dll, updating this is not necessary but who knows maybe we will need it later dunno.
			p_optional_header->ImageBase += delta;
		}

		//Step 2 populate IAT

		//ok so you can just do the IAT and call it a day. I decided to try to also support bound imports as far as I understood its there for optimization and avoiding the memory manager to make a
		//virtual copy of the page which would mean every process would have an own copy of the data instead of sharing it in physical memory <- this however does not really affect us its more of a
		//normal windows loader for normal xD dlls issue. I don't really care about performance on this project otherwise I would have written a lot of stuff differently but since this project is meant to
		//be a reference for me and maybe for others I am going to add bound import checks not really a stable and useful one but enough to get the idea how it may work.

		PIMAGE_DATA_DIRECTORY p_data_dir_imports = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		PIMAGE_IMPORT_DESCRIPTOR p_import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(p_data_dir_imports->VirtualAddress + allocated_dll);

		//Bound imports (this is optional)
		PIMAGE_DATA_DIRECTORY p_data_bound_imports_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
		PIMAGE_BOUND_IMPORT_DESCRIPTOR p_bound_import_desc = reinterpret_cast<PIMAGE_BOUND_IMPORT_DESCRIPTOR>(p_data_bound_imports_dir->VirtualAddress + allocated_dll);

		//OffsetModuleName This field is an offset (not an RVA) from the first IMAGE_BOUND_IMPORT_DESCRIPTOR. More info to this and the EAT can be found here:
		//https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2 
		//BYTE* bp_first_bound_desc = reinterpret_cast<BYTE*>(p_bound_import_desc); not going to use it since making a string comparision would not just require more code bloat but also restructuring the iat fix

		bool handle_bound_imports = false;

		//if we needed to relocate im better off just straight-up fixing iat however getting rva of function then adding delta would also work (still faster than EAT walk)
		if (p_data_bound_imports_dir->Size && !buffer->needs_reloc_fix && (buffer->flags & MI_BOUND_IMPORTS))
			handle_bound_imports = true; 

		if(p_data_dir_imports->Size)
		{
			for (; p_import_desc && p_import_desc->Name; p_import_desc++)
			{
				//this is the one we need to populate
				PIMAGE_THUNK_DATA pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(p_import_desc->FirstThunk + allocated_dll);
				PIMAGE_THUNK_DATA pOriginalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(p_import_desc->OriginalFirstThunk + allocated_dll);

				//at this stage both structure contain the same data on disk/memory therefore we can use the first thunk in case the original thunk is null or invalid
				if (!pOriginalThunk)
					pOriginalThunk = pFirstThunk;

				const char* const p_import_dll_name = reinterpret_cast<const char* const>(p_import_desc->Name + allocated_dll);
				//My Custom "LoadLibrary" function uses the official LoadLibrary im just checking if the module is already loaded
				//Manual Mapping the dependencies as well would be better might do it for my own stuff at some point who knows...(note for me if I do it keep in mind to consider reference count depending how you map it)
				void* dll_base = buffer->pfLoadLibraryAEx(p_import_dll_name, buffer);

				if(!dll_base)
					continue;

				//All of this is optional it belongs to my bad implemented bound import check
				//I am assuming that the bound imports OffsetModuleName have the same order as the ones in the import descriptor
				//Also I am assuming that the last bound import is indicated by TimeDateStamp being 0 otherwise you could go and check if p_bound_import_desc reached end just as I did in delayed imports
				if(handle_bound_imports && p_bound_import_desc->TimeDateStamp != 0)
				{
					//afaik when this is true the IAT is already filled with the fixed addresses. If I am wrong please tell me I didn't really spend much learning about bound imports
					if(reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PIMAGE_DOS_HEADER>(dll_base)->e_lfanew + reinterpret_cast<BYTE*>(dll_base))->FileHeader.TimeDateStamp == p_bound_import_desc->TimeDateStamp)
					{
						//Please don't take all of my words about bound imports as correct, I have spent 20 minutes reading about it, I can imagine doing a lot of stuff wrong here xD
						//also this is in no way a proper bound import support lol
						if(p_bound_import_desc->NumberOfModuleForwarderRefs)
						{
							/* 
							 *	++p_bound_import_desc;
							 *	reinterpret_cast<PIMAGE_BOUND_FORWARDER_REF>(p_bound_import_desc)->TimeDateStamp == next dll in OffsetModuleName;
							 *	you would want to loop through every single NumberOfModuleForwarderRefs
							 */

							//skipping until we get back to a PIMAGE_BOUND_IMPORT_DESCRIPTOR
							p_bound_import_desc += p_bound_import_desc->NumberOfModuleForwarderRefs;
						}
						else
						{
							++p_bound_import_desc;
							continue;
						}
					}

					++p_bound_import_desc;
				}//this is the end of my bad implemented bound import check everything below it belongs to the initial IAT fix

				for (; pOriginalThunk && pOriginalThunk->u1.AddressOfData; pFirstThunk++, pOriginalThunk++)
				{
					if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
					{
						// IMAGE_ORDINAL() does & 0xffff why? bcs an ordinal is a word 16 bit 2 byte value we dont want the msb flag in there or anything else just the ordinal
						pFirstThunk->u1.AddressOfData = reinterpret_cast<ULONG_PTR>(buffer->pfGetProcAddress(dll_base, pOriginalThunk->u1.Ordinal & 0xFFFF, buffer));
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME p_import_function_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pOriginalThunk->u1.AddressOfData + allocated_dll);
						//its a union you can do this or *pFirstThunk but it needs to be casted to an integer type before
						pFirstThunk->u1.AddressOfData = reinterpret_cast<ULONG_PTR>(buffer->pfGetProcAddress(dll_base, reinterpret_cast<std::uintptr_t>(p_import_function_name->Name), buffer));
					}
				}
			}

		}

		//Step 3 Resolve delay import table
		if(buffer->flags & MI_DELAY_IMPORTS)
		{
			PIMAGE_DATA_DIRECTORY p_delay_import_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

			if (p_delay_import_dir->Size)
			{
				PIMAGE_DELAYLOAD_DESCRIPTOR p_delay_import_desc = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(p_delay_import_dir->VirtualAddress + allocated_dll);

				void* p_delay_dir_end = p_delay_import_dir->Size + allocated_dll + p_delay_import_dir->VirtualAddress;

				for (; p_delay_import_desc && p_delay_import_desc->DllNameRVA && p_delay_import_desc < p_delay_dir_end; ++p_delay_import_desc)
				{
					if (!p_delay_import_desc->ModuleHandleRVA)
						continue;

					PIMAGE_THUNK_DATA p_delay_name_table = reinterpret_cast<PIMAGE_THUNK_DATA>(p_delay_import_desc->ImportNameTableRVA + allocated_dll);
					PIMAGE_THUNK_DATA p_delay_function_table = reinterpret_cast<PIMAGE_THUNK_DATA>(p_delay_import_desc->ImportAddressTableRVA + allocated_dll);

					if (!p_delay_name_table)
						p_delay_name_table = p_delay_function_table;

					const char* const dll_name = reinterpret_cast<const char* const>(p_delay_import_desc->DllNameRVA + allocated_dll);
					*reinterpret_cast<HMODULE*>(p_delay_import_desc->ModuleHandleRVA + allocated_dll) = reinterpret_cast<HINSTANCE>(buffer->pfLoadLibraryAEx(dll_name, buffer));

					for (; p_delay_name_table && p_delay_name_table->u1.AddressOfData; ++p_delay_name_table, ++p_delay_function_table)
					{
						HMODULE dll_base = reinterpret_cast<HMODULE>(p_delay_import_desc->ModuleHandleRVA + allocated_dll);
						//yeah I know union we can also just dereference but I feel like this is a bit easier to read/understand.
						if (IMAGE_SNAP_BY_ORDINAL(p_delay_name_table->u1.Ordinal))
							p_delay_function_table->u1.Function = reinterpret_cast<ULONG_PTR>(buffer->pfGetProcAddress(dll_base, p_delay_name_table->u1.Ordinal & 0xFFFF, buffer));
						else
						{
							PIMAGE_IMPORT_BY_NAME p_delay_function_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(p_delay_name_table->u1.AddressOfData + allocated_dll);
							p_delay_function_table->u1.Function = reinterpret_cast<ULONG_PTR>(buffer->pfGetProcAddress(dll_base, reinterpret_cast<std::uintptr_t>(p_delay_function_name->Name), buffer));
						}
					}
				}
			}
		}

		//Step 4 making exception handling partially work
		//more about SEH and RUNTIME_FUNCTION https://stackoverflow.com/questions/19808172/struct-runtime-function
		//SafeSEH possible solutions https://www.ownedcore.com/forums/world-of-warcraft/world-of-warcraft-bots-programs/wow-memory-editing/284617-manual-mapping-seh-handler-validation-aka-safeseh.html
		//x86 is RtlInsertInvertedFunctionTable -> RtlAddFunctionTable is x64 only and my mapper is x64 only anyway so im good
		if(buffer->flags & MI_EXCEPTION_SUPPORT)
		{
			PIMAGE_DATA_DIRECTORY p_exception_entry = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			if (p_exception_entry->Size && p_exception_entry->VirtualAddress)
			{
				if(!buffer->pfRtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(allocated_dll + p_exception_entry->VirtualAddress), p_exception_entry->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), reinterpret_cast<DWORD64>(buffer->allocated_dll)))
				{
					//Might use this in future but rn it does nothing im not checking anywhere else if this failed or not
					//TODO rpm after execution and log if failure or not
					buffer->exception_failed = false;
				}
			}
		}

		//Step 5 initializing Security Cookie (im just going to copy the code from the msvc compiler) cl.exe pdb ida will get you the pdb automatically then search for security cookie lol
		//actually I will make my own small cookie init fuck this I would need to call 3 diff functions to make the one cl is using
		if(buffer->flags & MI_SECURITY_COOKIE)
		{
			PIMAGE_DATA_DIRECTORY p_data_load_config = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
			PIMAGE_LOAD_CONFIG_DIRECTORY p_load_config_dir = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(p_data_load_config->VirtualAddress + allocated_dll);

			if (p_load_config_dir->SecurityCookie == 0x2B992DDFA232)
			{
				std::uintptr_t new_cookie = 0x1337;
				new_cookie ^= (p_optional_header->ImageBase & 0xFFFFFFFF) ^ (p_optional_header->SizeOfImage >> 16);
				new_cookie += p_optional_header->Magic;
				new_cookie ^= (static_cast<unsigned long long>(p_data_dir_imports->Size) * 0x5A);

				if (new_cookie == 0x2B992DDFA232)
					new_cookie += 0x100;

				p_load_config_dir->SecurityCookie = ~new_cookie;
			}
		}

		//Step 6 fixing section protections

		PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_header);
		for (std::size_t index = 0; index < p_nt_header->FileHeader.NumberOfSections; index++)
		{
			DWORD original_protection = PAGE_NOACCESS;
			DWORD old_protection = 0;
			if(p_section_header->SizeOfRawData)
			{
				if (p_section_header[index].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					original_protection |= PAGE_EXECUTE;
				if (p_section_header[index].Characteristics & IMAGE_SCN_MEM_READ)
					original_protection |= PAGE_READONLY;
				if (p_section_header[index].Characteristics & IMAGE_SCN_MEM_WRITE)
					original_protection |= PAGE_READWRITE;

				if ((original_protection & PAGE_EXECUTE) && (original_protection & PAGE_READWRITE))
				{
					original_protection = PAGE_EXECUTE_READWRITE;
				}
				else if ((original_protection & PAGE_EXECUTE) && (original_protection & PAGE_READONLY))
				{
					original_protection = PAGE_EXECUTE_READ;
				}
				buffer->pfVirtualProtect(p_section_header[index].VirtualAddress + allocated_dll, p_section_header->SizeOfRawData, original_protection, &old_protection);
			}
		}

		{
			//Dos and Pe header...
			DWORD dummy;
			buffer->pfVirtualProtect(allocated_dll, 1 << 12, PAGE_READONLY, &dummy);
		}

		//Step 7 handling TLS data
		if(buffer->flags & MI_TLS)
		{
			PIMAGE_DATA_DIRECTORY p_tls_entry = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
			PIMAGE_TLS_DIRECTORY p_tls_dir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(p_tls_entry->VirtualAddress + allocated_dll);

			//In case this option is checked but the loaded dll has no tls data which can lead to major issues especially when handle hijacking
			if(p_tls_entry->Size)
			{
				//this is the reason why we disabled security cookies for this function
				LDR_DATA_TABLE_ENTRY data_table_entry{ .DllBase = allocated_dll };
				//static tls data fix
				(void)buffer->pfLdrpHandleTlsData(&data_table_entry);

				if (PIMAGE_TLS_CALLBACK* p_tls_callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(p_tls_dir->AddressOfCallBacks))
				{
					for (; p_tls_callbacks && *p_tls_callbacks; p_tls_callbacks++)
					{
						//ctrl + click on PIMAGE_TLS_CALLBACK it literally says ULONGLONG AddressOfCallBacks; // PIMAGE_TLS_CALLBACK *;
						//kinda makes sense array of function pointers lol
						(*p_tls_callbacks)(allocated_dll, DLL_PROCESS_ATTACH, nullptr);
					}
				}

				//since LdrpHandleTlsData invokes LdrpAllocateTlsEntry the modules tls entry is added to the LdrpTlsList afaik, and we want ours to be removed
				//since it contains our dll base address which we specified in the LdrDataTableEntry (PLIST_ENTRY -> ModuleEntry -> LdrDataTableEntry -> .DllBase = allocated_dll)
				//thats how I understood it the code is from the gh injector without it, I would have left the stuff in the tlslist lol
				//if you want to check where its being used yourself go into ida press g and paste LdrpTlsList you can go from there
				for (PLIST_ENTRY curr = buffer->pLdrpTlsList->Flink; curr != buffer->pLdrpTlsList; curr = curr->Flink)
				{
					PTLS_ENTRY ptls_entry = reinterpret_cast<PTLS_ENTRY>(curr);
					if (ptls_entry->ModuleEntry == reinterpret_cast<void*>(&data_table_entry))
					{
						ptls_entry->ModuleEntry = nullptr;
						break;
					}
				}
			}
		}

		//Step 8 invoking dllmain
		typedef BOOL(WINAPI* DllMain)(
			HINSTANCE hinstDLL,
			DWORD fdwReason,
			LPVOID lpvReserved);

		(void)reinterpret_cast<DllMain>(p_optional_header->AddressOfEntryPoint + allocated_dll) (reinterpret_cast<HINSTANCE>(buffer->allocated_dll), DLL_PROCESS_ATTACH, nullptr);

		if(buffer->flags & MI_MODIFY_MODULE)
			buffer->pfApplyModuleModifications(buffer);

		buffer->execution_finished = true;
	}

	__declspec(safebuffers) static void* __stdcall GetProcAddressShellcode(void* const dll_base, std::uintptr_t function, MANUAL_MAP_BUFFER* buffer)
	{
		if (!dll_base || !buffer)
			return nullptr;

		BYTE* b_dll_base = reinterpret_cast<BYTE*>(dll_base);
		PIMAGE_DOS_HEADER p_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_base);
		PIMAGE_NT_HEADERS p_pe_header = reinterpret_cast<PIMAGE_NT_HEADERS>(p_dos_header->e_lfanew + b_dll_base);

		PIMAGE_DATA_DIRECTORY p_data_dir = &p_pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		PIMAGE_EXPORT_DIRECTORY p_export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(p_data_dir->VirtualAddress + b_dll_base);

		//array table list call it whatever you want
		DWORD* function_arr = reinterpret_cast<DWORD*>(p_export_dir->AddressOfFunctions + b_dll_base);
		WORD* ordinal_arr = reinterpret_cast<WORD*>(p_export_dir->AddressOfNameOrdinals + b_dll_base);
		DWORD* function_name_arr = reinterpret_cast<DWORD*>(p_export_dir->AddressOfNames + b_dll_base);

		void* found_function = nullptr;

		//checking if we passed an ordinal or a pointer
		if ( (function >> 16) == 0 )
		{
			WORD ordinal = static_cast<WORD>(function & 0xffff);

			if (ordinal < p_export_dir->Base || ordinal >= p_export_dir->Base + p_export_dir->NumberOfFunctions)
				return nullptr;

			found_function = function_arr[ordinal - p_export_dir->Base] + b_dll_base;
		}
		else
		{
			for (std::size_t index = 0; index < p_export_dir->NumberOfNames; index++)
			{
				//our parameter "function" will always be a pointer to a null terminated string, or at least should be
				//we could also use RtlCompareString and RtlInitAnsiString however requires a bigger buffer and I made the decision to use the dos header for my stuff xDDD Update dos header is no longer our buffer lol
				//maybe better I used the dos header otherwise I would have added 20 more functions for string manipulation which also require these bloated structures xDD Update yes we found a better way because of this 
				const char* function_name_in_table = reinterpret_cast<const char*>(function_name_arr[index] + b_dll_base);
				const char* function_to_find_name = reinterpret_cast<const char*>(function);

				bool equal = true;
				for (;*function_name_in_table && *function_to_find_name; function_name_in_table++, function_to_find_name++)
				{
					if (*function_name_in_table != *function_to_find_name)
					{
						equal = false;
						break;
					}
				}

				//if both strings are at the end and they matched before we gucci. 
				if(equal && (*function_name_in_table == *function_to_find_name) )
				{
					found_function = function_arr[ordinal_arr[index]] + b_dll_base;
					break;
				}
			}
		}

		//handle case if function is forwarded, how do we know? well look at the condition xD if the address we got is in the range of the IMAGE_DIRECTORY_ENTRY_EXPORT in our case p_data_dir
		//we know that found_function will point to a string which tells us the function name and the dll that it's supposed to be forwarded to. something like this dll_name.function_name
		if(found_function >= p_export_dir && found_function < reinterpret_cast<void*>(p_data_dir->VirtualAddress + p_data_dir->Size + b_dll_base))
		{
			//we can use RtlSplitUnicodeString however we would need to convert to a wide char which is a pain in the ass for me rn

			//Step 0 find the DOT and split those 2 strings

			const char* forwarded_function_str = reinterpret_cast<const char*>(found_function);

			std::size_t index_to_dot = 0;
			for (std::size_t index = 0; forwarded_function_str[index] ; index++)
			{
				if(forwarded_function_str[index] == '.')
				{
					index_to_dot = index;
					break; 
				}
			}

			//fun fact having a local array will make your compiler add security cookies which will cause your shit to crash xD 
			//__declspec(safebuffers) https://learn.microsoft.com/en-us/cpp/cpp/safebuffers?view=msvc-170&viewFallbackFrom=vs-2017 is here to save us 
			char forward_dll[MAX_PATH] {};
			if(index_to_dot < MAX_PATH - 1)
			{
				for (size_t i = 0; i < index_to_dot; i++)
				{
					forward_dll[i] = forwarded_function_str[i];
				}
				forward_dll[index_to_dot] = '\0';
			}

			const char* forward_function_name = forwarded_function_str + index_to_dot + 1;

			//if you don't want to pass buffer as an additional argument you can resolve LoadLibrary yourself inside the function as well (storing it will be the issue except you don't care resolving it for every single call),
			//won't make much sense for me since im using a custom one
			HMODULE forward_dll_base = reinterpret_cast<HINSTANCE>(buffer->pfLoadLibraryAEx(forward_dll, buffer));

			//Update future me here
			//yes I could also simply invoke my function normally like this GetProcAddressShellcode(forward_dll_base, reinterpret_cast<std::uintptr_t>(forward_function_name), buffer)
			//since the call is a relative one I checked it in ida E8 0A FC FF FF call oManualMapper__GetProcAddressShellcode, so it will always just go -1014 from next IP which is always valid
			//I did not think/realize it, so I made this, also optimization is off here so idk maybe Im lucky its relative, does not matter since im using this which is independent of the generated assembly.
			//maybe there is a trick to make everything into one section (I already did this all of this is in section .mMx) then be able to call all of our functions relative without any function pointers dunno just had a random thought.
			//yes that would work calling ManualMapShellcode(nullptr) should not lead to any issues for example, this would also be relative since its super close and in one small section
			//but in order for this to work I would need to allocate the entire section in 1 allocation not split in functions which is what I did therefore I need to work with function pointers now
			//for anyone else making their own shit don't do it like I did it, allocate the entire section and start execution at the beginning of the section which would be the function ManualMapShellcode
			//then use every function which is inside that section as normal no need for function pointers or that bloat to allocate every single fucking function, holy shit I just realized I wasted 100's of lines
			//of code for nothing damn :(
			return buffer->pfGetProcAddress(forward_dll_base, reinterpret_cast<std::uintptr_t>(forward_function_name), buffer);
		}

		return found_function;
	}

	__declspec(safebuffers) static void* __stdcall LoadLibraryShellcode(const char* dll_name, MANUAL_MAP_BUFFER* buffer)
	{
		PPEB pPEB = reinterpret_cast<PPEB>(__readgsqword(0x60));

		void* pMemoryOrderListHead = &pPEB->Ldr->InMemoryOrderModuleList;

		for (PLIST_ENTRY curr = pPEB->Ldr->InMemoryOrderModuleList.Flink; curr != pMemoryOrderListHead; curr = curr->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			wchar_t w_dll_name[MAX_PATH];
			buffer->pfMultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, dll_name, -1, w_dll_name, MAX_PATH);

			const wchar_t* function_name_in_table = pLdrEntry->BaseDllName.Buffer;
			const wchar_t* function_to_find_name  = w_dll_name;

			bool equal = true;
			for (; *function_name_in_table && *function_to_find_name; function_name_in_table++, function_to_find_name++)
			{
				if (*function_name_in_table != *function_to_find_name)
				{
					equal = false;
					break;
				}
			}

			//if both strings are at the end and they matched before we gucci. 
			if (equal && (*function_name_in_table == *function_to_find_name))
				return pLdrEntry->DllBase;
		}
		
		buffer->pfRtlZeroMemory(&buffer->module_name, sizeof(UNICODE_STRING));
		buffer->pfRtlZeroMemory(&buffer->path_sc, sizeof(LDRP_PATH_SEARCH_CONTEXT));
		buffer->pfRtlZeroMemory(&buffer->lc_flags, sizeof(LDRP_LOAD_CONTEXT_FLAGS));
		buffer->ldr_entry = nullptr;

		buffer->pfBasep8BitStringToDynamicUnicodeString(&buffer->module_name, dll_name);
		buffer->pfLdrpLoadDll(&buffer->module_name, &buffer->path_sc, buffer->lc_flags, &buffer->ldr_entry);
		return buffer->ldr_entry->DllBase;
	}

	__declspec(safebuffers) static void __stdcall ApplyModuleModifications(MANUAL_MAP_BUFFER* buffer)
	{
		BYTE* dll_base = reinterpret_cast<BYTE*>(buffer->allocated_dll);

		PIMAGE_DOS_HEADER p_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer->allocated_dll);
		PIMAGE_NT_HEADERS p_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer->e_lfanew + dll_base);

		PIMAGE_FILE_HEADER p_file_header = &p_nt_header->FileHeader;
		PIMAGE_OPTIONAL_HEADER p_optional_header = &p_nt_header->OptionalHeader;

		BYTE txt_section[IMAGE_SIZEOF_SHORT_NAME] = { '.','t','e','x','t','\0' }; //doing ".text" .rdata:000000018002D620: 

		PIMAGE_SECTION_HEADER const p_section_header = IMAGE_FIRST_SECTION(p_nt_header);
		for (std::size_t index = 0; index < p_nt_header->FileHeader.NumberOfSections; index++)
		{
			BYTE* text_section = txt_section;
			BYTE* curr_section = p_section_header[index].Name;

			bool equal = true;
			for (; *text_section && *curr_section; text_section++, curr_section++)
			{
				if (*text_section != *curr_section)
				{
					equal = false;
					break;
				}
			}

			if (equal && (*text_section == *curr_section))
				continue;

			DWORD old_protection;
			if (p_section_header->SizeOfRawData)
				buffer->pfVirtualProtect(p_section_header[index].VirtualAddress + dll_base, p_section_header->SizeOfRawData, PAGE_READWRITE, &old_protection);
		}

		{
			//Dos and Pe header...
			DWORD dummy;
			buffer->pfVirtualProtect(dll_base, 1 << 12, PAGE_READWRITE, &dummy);
		}

		{//I am sorry for doing this but my names are so weird im just trying to avoid dumb mistakes
			//Mod 1: Bound Import
			if(buffer->flags & MI_REMOVE_BOUND_IMPORTS)
			{
				PIMAGE_DATA_DIRECTORY p_bound_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
				if (p_bound_dir->Size)
				{
					PIMAGE_BOUND_IMPORT_DESCRIPTOR p_bound_desc = reinterpret_cast<PIMAGE_BOUND_IMPORT_DESCRIPTOR>(p_bound_dir->VirtualAddress + dll_base);

					BYTE* start_desc = reinterpret_cast<BYTE*>(p_bound_desc);
					for (; p_bound_desc->TimeDateStamp; ++p_bound_desc)
					{
						*reinterpret_cast<void**>(p_bound_desc->OffsetModuleName + start_desc) = nullptr;
						p_bound_desc->TimeDateStamp = 0;
						p_bound_desc->NumberOfModuleForwarderRefs = 0;
					}

					p_bound_dir->VirtualAddress = 0;
				}
				else
					p_bound_dir->VirtualAddress = 0; //why not yes this one should be 0 if the size is 0 but but now looking at it, I realize I wasted my time writing this
			}
		}
		
		{
			//Mod 2: Imports and Delay Imports
			if(buffer->flags & MI_REMOVE_IMPORTS)
			{
				PIMAGE_DATA_DIRECTORY p_import_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
				if (p_import_dir->Size)
				{
					PIMAGE_IMPORT_DESCRIPTOR p_import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(p_import_dir->VirtualAddress + dll_base);

					void* dir_end = p_import_dir->Size + p_import_dir->VirtualAddress + dll_base;
					for (; p_import_desc < dir_end && p_import_desc->Name; p_import_desc++)
					{
						PIMAGE_THUNK_DATA p_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(p_import_desc->FirstThunk + dll_base);
						PIMAGE_THUNK_DATA p_original_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(p_import_desc->OriginalFirstThunk + dll_base);

						for (; p_original_thunk && p_original_thunk->u1.AddressOfData; ++p_file_header, ++p_original_thunk)
						{
							//Keep in mind names are not cleared however the offset to the IMAGE_IMPORT_BY_NAME is gone
							p_original_thunk->u1.AddressOfData = 0;
							p_first_thunk->u1.AddressOfData = 0;
						}

						p_import_desc->FirstThunk = 0;
						p_import_desc->ForwarderChain = 0;
						p_import_desc->Name = 0;
						p_import_desc->TimeDateStamp = 0;
					}

					p_import_dir->VirtualAddress = 0;
				}
				else
					p_import_dir->VirtualAddress = 0;

				PIMAGE_DATA_DIRECTORY p_delay_import_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
				if (p_delay_import_dir->Size)
				{
					PIMAGE_DELAYLOAD_DESCRIPTOR p_delay_desc = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(p_delay_import_dir->VirtualAddress + dll_base);

					void* p_delay_dir_end = p_delay_import_dir->Size + dll_base + p_delay_import_dir->VirtualAddress;

					for (; p_delay_desc && p_delay_desc->DllNameRVA && p_delay_desc < p_delay_dir_end; ++p_delay_desc)
					{
						PIMAGE_THUNK_DATA p_delay_name_table = reinterpret_cast<PIMAGE_THUNK_DATA>(p_delay_desc->ImportNameTableRVA + dll_base);
						PIMAGE_THUNK_DATA p_delay_function_table = reinterpret_cast<PIMAGE_THUNK_DATA>(p_delay_desc->ImportAddressTableRVA + dll_base);

						*reinterpret_cast<HMODULE*>(p_delay_desc->ModuleHandleRVA + dll_base) = nullptr;

						for (; p_delay_name_table->u1.AddressOfData; ++p_delay_name_table, ++p_delay_function_table)
						{
							p_delay_name_table->u1.Function = 0;
							p_delay_function_table->u1.AddressOfData = 0;
						}
					}

					p_delay_desc->TimeDateStamp = 0;
					p_delay_desc->DllNameRVA = 0;
					p_delay_desc->Attributes.AllAttributes = 0;
					p_delay_desc->BoundImportAddressTableRVA = 0;
					p_delay_desc->ImportAddressTableRVA = 0;
					p_delay_desc->ImportNameTableRVA = 0;
					p_delay_desc->ModuleHandleRVA = 0;
					p_delay_desc->UnloadInformationTableRVA = 0;

					p_delay_import_dir->VirtualAddress = 0;
				}
				else
					p_delay_import_dir->VirtualAddress = 0;
			}
		}
		
		
		{
			//Mod 3: Relocs
			if(buffer->flags & MI_REMOVE_RELOCATIONS)
			{
				PIMAGE_DATA_DIRECTORY p_reloc_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
				if (p_reloc_dir->Size)
				{
					PIMAGE_BASE_RELOCATION p_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(p_reloc_dir->VirtualAddress + dll_base);
					while (p_reloc->VirtualAddress)
					{
						//Future me here just looked at how gh injector did this and he used RtlZeroMemory(reloc_arr, block_size) well looks like I fucked up once again
						//will leave this tho mine is slower but then again maybe not bad to see 2 diff implementations?? also keep in mind when using RtlZeroMemory we need block size to be in bytes so just don't divide my sizeof(WORD)
						size_t block_size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
						WORD* reloc_arr = reinterpret_cast<WORD*>(p_reloc + 1);

						for (size_t index = 0; index < block_size; index++)
						{
							for (size_t i = 0; i < block_size; i++)
								reloc_arr[index] = 0;
						}

						BYTE* temp_reloc = reinterpret_cast<BYTE*>(p_reloc);
						size_t temp_block_size = p_reloc->SizeOfBlock;

						p_reloc->SizeOfBlock = 0;
						p_reloc->VirtualAddress = 0;

						p_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(temp_reloc + temp_block_size);
					}

					p_reloc_dir->VirtualAddress = 0;
				}
				else
					p_reloc_dir->VirtualAddress = 0;
			}
		}
		
		{
			//Mod 4: Resources Don't flame me if I get this wrong I don't even know why I even bother with this one
			if(buffer->flags & MI_REMOVE_RESOURCES)
			{
				PIMAGE_DATA_DIRECTORY p_rsrc_dir = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
				if (p_rsrc_dir->Size)
				{
					PIMAGE_RESOURCE_DIRECTORY p_rsrc = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(p_rsrc_dir->VirtualAddress + dll_base);

					for (size_t i = 0; i < p_rsrc->NumberOfIdEntries; i++)
					{
						PIMAGE_RESOURCE_DIRECTORY_ENTRY p_rsrc_entry = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(&p_rsrc[i]);
						p_rsrc_entry->Name = 0;
						p_rsrc_entry->OffsetToData = 0;
					}

					p_rsrc->TimeDateStamp = 0;
					p_rsrc->Characteristics = 0;
					p_rsrc->MajorVersion = 0;
					p_rsrc->MinorVersion = 0;
					p_rsrc->NumberOfIdEntries = 0;
					p_rsrc->NumberOfNamedEntries = 0;

					p_rsrc_dir->VirtualAddress = 0;
				}
				else
					p_rsrc_dir->VirtualAddress = 0;
			}
		}
		
		{
			//Mod 5: Export Table
			if(buffer->flags & MI_REMOVE_EXPORT_TABLE)
			{
				PIMAGE_DATA_DIRECTORY p_export_data = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				if (p_export_data->Size)
				{
					PIMAGE_EXPORT_DIRECTORY p_export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(p_export_data->VirtualAddress + dll_base);

					DWORD* function_arr = reinterpret_cast<DWORD*>(p_export_dir->AddressOfFunctions + dll_base);
					WORD* ordinal_arr = reinterpret_cast<WORD*>(p_export_dir->AddressOfNameOrdinals + dll_base);
					DWORD* function_name_arr = reinterpret_cast<DWORD*>(p_export_dir->AddressOfNames + dll_base);

					for (size_t i = 0; i < p_export_dir->NumberOfNames; i++)
					{
						function_arr[i] = 0;
						ordinal_arr[i] = 0;
						function_name_arr[i] = 0;
					}

					p_export_dir->Name = 0;
					p_export_dir->Base = 0;
					p_export_dir->AddressOfFunctions = 0;
					p_export_dir->AddressOfNameOrdinals = 0;
					p_export_dir->AddressOfNames = 0;
					p_export_dir->TimeDateStamp = 0;
					p_export_dir->Characteristics = 0;
					p_export_dir->MajorVersion = 0;
					p_export_dir->MinorVersion = 0;
					p_export_dir->NumberOfNames = 0;
					p_export_dir->NumberOfFunctions = 0;

					p_export_data->VirtualAddress = 0;
				}
				else
					p_export_data->VirtualAddress = 0;
			}
		}
		
		{
			//Mod 6: Tls
			if(buffer->flags & MI_REMOVE_TLS)
			{
				PIMAGE_DATA_DIRECTORY p_tls_data = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
				if (p_tls_data->Size)
				{
					PIMAGE_TLS_DIRECTORY p_tls_dir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(p_tls_data->VirtualAddress + dll_base);

					void** tls_callbacks = reinterpret_cast<void**>(p_tls_dir->AddressOfCallBacks);
					for (; tls_callbacks && *tls_callbacks; tls_callbacks++)
						*tls_callbacks = nullptr;

					p_tls_dir->AddressOfCallBacks = 0;
					p_tls_dir->AddressOfIndex = 0;
					p_tls_dir->EndAddressOfRawData = 0;
					p_tls_dir->SizeOfZeroFill = 0;
					p_tls_dir->StartAddressOfRawData = 0;
				}
				else
					p_tls_data->VirtualAddress = 0;
			}
		}
		
		{
			//Mod 7: Debug data
			if(buffer->flags & MI_REMOVE_DEBUG_DATA)
			{
				PIMAGE_DATA_DIRECTORY p_debug_data = &p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
				if (p_debug_data->Size)
				{
					//Does not actually clean everything since im not looping through the entire debug directory however the first entry usually being CodeView it should be enough
					PIMAGE_DEBUG_DIRECTORY p_debug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(p_debug_data->VirtualAddress + dll_base);

					buffer->pfRtlZeroMemory(dll_base + p_debug_dir->AddressOfRawData, p_debug_dir->SizeOfData);
					buffer->pfRtlZeroMemory(p_debug_dir, sizeof(PIMAGE_DEBUG_DIRECTORY));

					p_debug_data->Size = 0;
					p_debug_data->VirtualAddress = 0;
				}
				else
					p_debug_data->VirtualAddress = 0;
			}
		}

		//So here I also wanted to add an option where the user could remove the .rsrc and .reloc sections oh as well as the .pdata section if the exception support flag is false
		//.pdata contains the RUNTIME_FUNCTION
		//I am not sure if I want to add even more stuff it's already really bloated here lol
		//I mean I could still add a bunch of useless stuff for instance a PE "spoofer" or whatever which walks peb picks random dll and copies everything into ours
		//Hell I could even make it so that every dependency we loaded with loadlibrary should also be manual mapped xD there are many ideas, but I got sick of this project I just want to be done
		//TODO maybe a new source file and unmap sections external?
		for (std::size_t index = 0; index < p_nt_header->FileHeader.NumberOfSections; index++)
		{
			BYTE* text_section = txt_section;
			BYTE* curr_section = p_section_header[index].Name;

			bool equal = true;
			for (; *text_section && *curr_section; text_section++, curr_section++)
			{
				if (*text_section != *curr_section)
				{
					equal = false;
					break;
				}
			}

			if (equal && (*text_section == *curr_section))
				continue;

			DWORD original_protection = PAGE_NOACCESS;
			DWORD old_protection = 0;
			if (p_section_header->SizeOfRawData)
			{
				if (p_section_header[index].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					original_protection |= PAGE_EXECUTE;
				if (p_section_header[index].Characteristics & IMAGE_SCN_MEM_READ)
					original_protection |= PAGE_READONLY;
				if (p_section_header[index].Characteristics & IMAGE_SCN_MEM_WRITE)
					original_protection |= PAGE_READWRITE;
		
				if ((original_protection & PAGE_EXECUTE) && (original_protection & PAGE_READWRITE))
				{
					original_protection = PAGE_EXECUTE_READWRITE;
				}
				else if ((original_protection & PAGE_EXECUTE) && (original_protection & PAGE_READONLY))
				{
					original_protection = PAGE_EXECUTE_READ;
				}
				buffer->pfVirtualProtect(p_section_header[index].VirtualAddress + dll_base, p_section_header->SizeOfRawData, original_protection, &old_protection);
			}
		}

		if(buffer->flags & MI_REMOVE_PE_HEADER)
		{
			size_t pe_size = sizeof(IMAGE_NT_HEADERS) + (p_file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
			buffer->pfRtlZeroMemory(p_nt_header, pe_size);
		}

		if(buffer->flags & MI_REMOVE_DOS_HEADER)
		{
			size_t dos_size = sizeof(IMAGE_DOS_HEADER);
			buffer->pfRtlZeroMemory(p_dos_header, dos_size);
		}

		if(buffer->flags & MI_REMOVE_RICH_HEADER)
		{
			size_t rich_header_size = reinterpret_cast<size_t>(p_nt_header) - reinterpret_cast<size_t>(dll_base) - 0x80; // 0x80 -> dos header and dos stub
			buffer->pfRtlZeroMemory(reinterpret_cast<BYTE*>(p_dos_header) + 0x80, rich_header_size);
		}

		if(buffer->flags & MI_REMOVE_DOS_STUB)
		{
			size_t dos_stub_size = 0x40; // 0x40 -> dos stub
			buffer->pfRtlZeroMemory(reinterpret_cast<BYTE*>(p_dos_header) + sizeof(IMAGE_DOS_HEADER), dos_stub_size);
		}

		{
			//Dos and Pe header...
			DWORD dummy;
			buffer->pfVirtualProtect(dll_base, 1 << 12, PAGE_READONLY, &dummy);
		}
	}

	static void __stdcall Dummy() { volatile int a = 0; std::cout << a; }

#pragma optimize("", on)
#pragma code_seg (pop)

	//Data we need to unload the manual mapped dll
	static void SaveUnloadData(void* const dll_on_disk ,void const* const allocated_dll, HANDLE process_handle, bool SEH)
	{
		BYTE* const dll_base = reinterpret_cast<BYTE* const>(dll_on_disk);

		PIMAGE_DOS_HEADER p_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_on_disk);
		PIMAGE_NT_HEADERS p_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(p_dos_header->e_lfanew + dll_base);

		BYTE const* const base = reinterpret_cast<BYTE const* const> (allocated_dll);

		IMAGE_NT_HEADERS nt_header {};
		(void)ReadProcessMemory(process_handle, base + p_dos_header->e_lfanew, &nt_header, sizeof(IMAGE_NT_HEADERS), nullptr);
		IMAGE_TLS_DIRECTORY tls_dir{};
		(void)ReadProcessMemory(process_handle, nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + base, &tls_dir, sizeof(IMAGE_TLS_DIRECTORY), nullptr);

		std::wstring root_path = GetModuleFilePath();
		size_t pos = root_path.rfind('\\');
		if (pos != std::wstring::npos)
		{
			root_path.erase(root_path.cbegin() + pos, root_path.cend());
			std::filesystem::path fixed_path = root_path;
			std::ofstream dll_info_file{ (fixed_path / "manual_mapped_dll_info.txt"), std::ios_base::trunc };
			dll_info_file << "Mapped Dll Base: \n" << allocated_dll << '\n'
			<< "AddressOfCallBacks: \n" << reinterpret_cast<void*>(tls_dir.AddressOfCallBacks) << '\n'
			<< "AddressOfEntryPoint: \n" << p_nt_headers->OptionalHeader.AddressOfEntryPoint << '\n'
			<< "Runtime Function Table: \n" << nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress << '\n'
			<< "SEH status: \n" << SEH << '\n'
			<< "Image Size: \n" << p_nt_headers->OptionalHeader.SizeOfImage << '\n';

			dll_info_file.close();
		}
	}

	bool ManualMapExecutionStub(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, const wchar_t* const exec_method, DWORD64 additional_flags, DWORD pid)
	{
		if (!wcscmp(exec_method, L"TlsCallback"))
			return oTlsCallback::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, additional_flags, pid);

		if (!wcscmp(exec_method, L"InstrumentationCallback"))
			return oInstrumentationCallback::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, additional_flags, pid);

		if (!wcscmp(exec_method, L"ThreadPool"))
			return oThreadPool::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, additional_flags, pid);

		if (!wcscmp(exec_method, L"CreateRemoteThread") || !wcscmp(exec_method, L"NtCreateThreadEx"))
			return oCreateThread::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, exec_method, additional_flags);

		if (!wcscmp(exec_method, L"KernelCallbackTable"))
			return oKernelCallbackTable::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, additional_flags, pid);

		if (!wcscmp(exec_method, L"QueueUserAPC"))
			return oQueueUserAPC::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, pid, true);

		if (!wcscmp(exec_method, L"SetWindowsHook"))
			return oSetWindowsHook::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, additional_flags, pid);

		if (!wcscmp(exec_method, L"VectoredExceptionHandler"))
			return oVectoredExceptionHandler::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data);

		if (!wcscmp(exec_method, L"ThreadHijack"))
			return oThreadHijack::Execute(process_handle, allocated_memory_code, allocated_memory_thread_data, pid, true);
	}

	void AdjustHandleFlags(DWORD& access_flags, const wchar_t* exec_method)
	{
		if (!wcscmp(exec_method, L"TlsCallback"))
			access_flags = access_flags | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

		if (!wcscmp(exec_method, L"InstrumentationCallback"))
			access_flags = access_flags | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SET_INFORMATION;

		if (!wcscmp(exec_method, L"ThreadPool"))
			access_flags = access_flags | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

		if (!wcscmp(exec_method, L"CreateRemoteThread") || !wcscmp(exec_method, L"NtCreateThreadEx"))
			access_flags = access_flags | PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | SYNCHRONIZE;

		if (!wcscmp(exec_method, L"KernelCallbackTable"))
			access_flags = access_flags | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

		if (!wcscmp(exec_method, L"QueueUserAPC"))
			access_flags = access_flags | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

		if (!wcscmp(exec_method, L"SetWindowsHook"))
			access_flags = access_flags | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;

		if (!wcscmp(exec_method, L"VectoredExceptionHandler"))
			access_flags = access_flags | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

		if (!wcscmp(exec_method, L"ThreadHijack"))
			access_flags = access_flags | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
	}

	bool Inject(const wchar_t* dllpath, DWORD pid, Injection_Method injection_method, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
		//TODO parse rich header
		//TODO SafeSEH needs custom VEH or hooking and changing flags in RtlIsValidHandler decide on which takes less code
		/* Useful functions for future use maybe https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntldr.h
		 * LdrFindEntryForAddress
		 * LdrProcessRelocationBlock
		 * LdrProcessRelocationBlockEx
		 * LdrRelocateImage
		 * LdrRelocateImageWithBias
		 * LdrGetDllPath
		 * LdrpGenericProcessRelocation
		 * LdrSetDllManifestProber
		 * LdrpManifestProberRoutine
		 * //https://xpdll.nirsoft.net/ntdll_dll.html
		 * RtlRegisterSecureMemoryCacheCallback
		 */

		DWORD access_flags = PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
		HANDLE process_handle = nullptr;

		AdjustHandleFlags(access_flags, exec_method);

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

		//checking file size is redundant imo the user should make sure he selected the correct dll
		std::ifstream file { dllpath, std::ios::binary | std::ios::ate };
		if (file.fail() && !file.is_open())
		{
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		std::streamsize dll_size = file.tellg();
		file.seekg(std::ios::beg);

		std::unique_ptr<BYTE[]> dll_base = std::make_unique<BYTE[]>(dll_size);
		file.read(reinterpret_cast<char*>(dll_base.get()), dll_size);

		file.close();

		PIMAGE_DOS_HEADER const p_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER const>(dll_base.get());

		//idk how someone can fuck this up and load a file that is not a dll into this injector but whatever. Maybe someone loads a dll that has no dos header on disk xDD
		if (strncmp(reinterpret_cast<const char*>(&p_dos_header->e_magic), "MZ", 2))
		{
			CONSOLE_LOG_ERROR("Invalid DOS header")
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		PIMAGE_NT_HEADERS const p_nt_headers			= reinterpret_cast<PIMAGE_NT_HEADERS const>(p_dos_header->e_lfanew + dll_base.get());
		PIMAGE_OPTIONAL_HEADER const p_optional_header	= &p_nt_headers->OptionalHeader;
		PIMAGE_FILE_HEADER const p_file_header			= &p_nt_headers->FileHeader;

		bool needs_reloc_fix = false;

		void* allocated_dll = VirtualAllocEx(process_handle, reinterpret_cast<void*>(p_optional_header->ImageBase), p_optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if(!allocated_dll)
		{
			needs_reloc_fix = true;
			CONSOLE_LOG_ERROR("Prefered Image Base allocation failed...")
			CONSOLE_LOG("Allocating Page at new address and relocating beginns...")

			allocated_dll = VirtualAllocEx(process_handle, nullptr, p_optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if(!allocated_dll)
			{
				CONSOLE_LOG_ERROR("Allocation failed")
				if (!is_inside_hijacked_process)
					process_handle ? CloseHandle(process_handle) : NULL;

				return false;
			}
		}

		if(!needs_reloc_fix)
			CONSOLE_LOG("Allocated at prefered Image Base skipping relocs")

		//Map all the sections into our allocated page
		//the macro should be self-explanatory, if not I will give you a hint the section headers start right after the optional header wait this isn't a hint anymore lol xD
		//another example to accomplish the same as that macro is doing this reinterpret_cast<PIMAGE_SECTION_HEADER>((BYTE*)&p_nt_headers->OptionalHeader + p_file_header->SizeOfOptionalHeader);
		PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_headers);
		for (size_t i = 0; i < p_file_header->NumberOfSections; i++, p_section_header++)
		{
			if(!WriteProcessMemory(process_handle, reinterpret_cast<BYTE*>(allocated_dll) + p_section_header->VirtualAddress, dll_base.get() + p_section_header->PointerToRawData, p_section_header->SizeOfRawData, nullptr))
			{
				Utility::FreeAllocatedMemoryEx(process_handle, "Whomp Whomp Writing Sections failed buhuu hu", allocated_dll);
				if (!is_inside_hijacked_process)
					process_handle ? CloseHandle(process_handle) : NULL;

				return false;
			}
		}

		//writing the dos header pe header... which is the first page 4kb 0x1000 or what I usually do 1 << 12
		if (!WriteProcessMemory(process_handle, allocated_dll, dll_base.get(), 1 << 12, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing failed", allocated_dll);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		const ULONG_PTR function_size_MMShellcode = reinterpret_cast<ULONG_PTR>(GetProcAddressShellcode) - reinterpret_cast<ULONG_PTR>(ManualMapShellcode);

		void* const allocation_functionManualMapShellcode = VirtualAllocEx(process_handle, nullptr, function_size_MMShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocation_functionManualMapShellcode)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Allocation for our Shellcode failed", allocated_dll);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		if (!WriteProcessMemory(process_handle, allocation_functionManualMapShellcode, ManualMapShellcode, function_size_MMShellcode, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing our Shellcode failed", allocated_dll, allocation_functionManualMapShellcode);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		//please dont hate on me for using 1 << 12 instead of 4096 I make a lot less typos with 1 << 12 even though it doesn't matter since it will always allocate on page boundary
		const ULONG_PTR function_size_GetProcAddr = reinterpret_cast<ULONG_PTR>(LoadLibraryShellcode) - reinterpret_cast<ULONG_PTR>(GetProcAddressShellcode);

		void* const allocation_functionMGetProcAddrShellcode = VirtualAllocEx(process_handle, nullptr, function_size_GetProcAddr, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocation_functionMGetProcAddrShellcode)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Allocation for our Shellcode failed", allocated_dll, allocation_functionManualMapShellcode);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		if (!WriteProcessMemory(process_handle, allocation_functionMGetProcAddrShellcode, GetProcAddressShellcode, function_size_GetProcAddr, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing our GetProc Shellcode failed", allocated_dll, allocation_functionManualMapShellcode, 
										   allocation_functionMGetProcAddrShellcode);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		const ULONG_PTR function_size_LoadLibrary = reinterpret_cast<ULONG_PTR>(ApplyModuleModifications) - reinterpret_cast<ULONG_PTR>(LoadLibraryShellcode);

		void* const allocation_functionLoadLibraryShellcode = VirtualAllocEx(process_handle, nullptr, function_size_LoadLibrary, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocation_functionLoadLibraryShellcode)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Allocation for our Shellcode failed", allocated_dll, allocation_functionManualMapShellcode, 
									       allocation_functionMGetProcAddrShellcode);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		if (!WriteProcessMemory(process_handle, allocation_functionLoadLibraryShellcode, LoadLibraryShellcode, function_size_LoadLibrary, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing our GetProc Shellcode failed", allocated_dll, allocation_functionManualMapShellcode, 
									       allocation_functionLoadLibraryShellcode, allocation_functionMGetProcAddrShellcode);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		const ULONG_PTR function_size_ApplyMods = reinterpret_cast<ULONG_PTR>(Dummy) - reinterpret_cast<ULONG_PTR>(ApplyModuleModifications);
		
		void* const allocation_functionApplyModuleModifications = VirtualAllocEx(process_handle, nullptr, function_size_ApplyMods, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocation_functionApplyModuleModifications)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Allocation for ApplyModuleModifications failed", allocated_dll, allocation_functionManualMapShellcode, 
							               allocation_functionLoadLibraryShellcode, allocation_functionMGetProcAddrShellcode);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		if (!WriteProcessMemory(process_handle, allocation_functionApplyModuleModifications, ApplyModuleModifications, function_size_ApplyMods, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing our ApplyModuleModifications Function failed", allocated_dll, allocation_functionManualMapShellcode, 
										   allocation_functionLoadLibraryShellcode, allocation_functionMGetProcAddrShellcode, allocation_functionApplyModuleModifications);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		void* const allocation_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(MANUAL_MAP_BUFFER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocation_buffer)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Allocation for our Buffer failed", allocated_dll, allocation_functionManualMapShellcode, 
									       allocation_functionLoadLibraryShellcode, allocation_functionMGetProcAddrShellcode, allocation_functionApplyModuleModifications);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		//I am going to try to use the DOS Header as my buffer

		//UPDATE future me here lol, so looks like I am a retard and doing this will cause some dlls to not work correctly I faced crashed on ZwTerminateThread syscall and was confused what I fucked up
		//looks like the dos header is quite important xD therefore I will make a new allocation just for my buffer however I will leave these old comments down here.
		//you can do it after dllmain tho.

		//What I initially did was using the Dos header and Dos stub + part of the rich header as my buffer which caused these weird crashes on some dlls with certain options enabled.
		//Was a dumb idea anyway since if a binary was not compiled with msvc it would not have the rich header therefore I would invalidate parts of the PE Header which is obv bad.
		//nonetheless the size of the rich header is not always the same, I think it always depends on how vs built it not sure though (~ 60-100 bytes)

		//Also yes it is possible to resolve most functions that are exported inside my shellcode im thinking about parsing peb for dll base and making a local array of chars with
		//hardcoded names for the function then resolving it with our own getprocaddr function however I will probably not do this. Functions that are not exported will need to be resolved here anyway.

		//Note: I wanted to change VirtualProtect to be NtProtectVirtualMemory however honestly since NtProtectVirtualMemory is usually hooked it won't matter at all here an indirect syscall
		//would be good however requires more code (as well for checks on instrumentation callback which would fuck me even harder than a NtProtectVirtualMemory hook xD)
		//the ideal way of doing this would be to change protection externally and notify that we completed the process and then continue in our shellcode (wpm in our buffer to notify to continue for example)
		//I am not going to do this, I will leave the stuff as it is
		MANUAL_MAP_BUFFER mm_buffer{};

		HMODULE kernel32_module = GetModuleHandleW(L"kernel32.dll");

		mm_buffer.allocated_dll							  = allocated_dll;
		mm_buffer.pfLdrpHandleTlsData					  = SymbolParser::FindFunction<LdrpHandleTlsData>("LdrpHandleTlsData");
		mm_buffer.pfRtlAddFunctionTable					  = RtlAddFunctionTable;
		mm_buffer.pfVirtualProtect						  = VirtualProtect;
		mm_buffer.e_lfanew								  = p_dos_header->e_lfanew;
		mm_buffer.pfLdrpLoadDll							  = SymbolParser::FindFunction<LdrpLoadDll>("LdrpLoadDll");
		mm_buffer.needs_reloc_fix						  = needs_reloc_fix;
		mm_buffer.pfGetProcAddress						  = reinterpret_cast<decltype(mm_buffer.pfGetProcAddress)>(allocation_functionMGetProcAddrShellcode);
		mm_buffer.pLdrpTlsList							  = SymbolParser::FindClass<PLIST_ENTRY>("LdrpTlsList");
		mm_buffer.pfMultiByteToWideChar					  = MultiByteToWideChar;
		mm_buffer.pfLoadLibraryAEx						  = reinterpret_cast<decltype(mm_buffer.pfLoadLibraryAEx)>(allocation_functionLoadLibraryShellcode);
		mm_buffer.pfRtlZeroMemory						  = SymbolParser::FindFunction<_RtlZeroMemory>("RtlZeroMemory");
		mm_buffer.pfApplyModuleModifications			  = reinterpret_cast<decltype(mm_buffer.pfApplyModuleModifications)>(allocation_functionApplyModuleModifications);
		mm_buffer.pfBasep8BitStringToDynamicUnicodeString = reinterpret_cast<Basep8BitStringToDynamicUnicodeString>(GetProcAddress(kernel32_module, "Basep8BitStringToDynamicUnicodeString"));

		mm_buffer.flags									  = additional_flags;

		if(!WriteProcessMemory(process_handle, allocation_buffer, &mm_buffer, sizeof(MANUAL_MAP_BUFFER), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing failed", allocated_dll, allocation_functionMGetProcAddrShellcode, 
									       allocation_functionManualMapShellcode, allocation_buffer, allocation_functionLoadLibraryShellcode, allocation_functionApplyModuleModifications);
			if (!is_inside_hijacked_process)
				process_handle ? CloseHandle(process_handle) : NULL;

			return false;
		}

		SaveUnloadData(p_dos_header, allocated_dll, process_handle, (additional_flags & MI_EXCEPTION_SUPPORT));
		SaveCurrentModulesToFile(pid);

		if(!ManualMapExecutionStub(process_handle, allocation_functionManualMapShellcode, allocation_buffer, exec_method, additional_flags, pid))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "Execution failed", allocation_buffer, allocation_functionManualMapShellcode, 
									       allocated_dll, allocation_functionMGetProcAddrShellcode, allocation_functionLoadLibraryShellcode, allocation_functionApplyModuleModifications);
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
				Utility::FreeAllocatedMemoryEx(process_handle, {}, allocation_buffer, allocation_functionManualMapShellcode, 
				                               allocated_dll, allocation_functionMGetProcAddrShellcode, allocation_functionLoadLibraryShellcode, allocation_functionApplyModuleModifications);
				if (!is_inside_hijacked_process)
					process_handle ? CloseHandle(process_handle) : NULL;

				return false;
			}

			ReadProcessMemory(process_handle, static_cast<BYTE*>(allocation_buffer) + offsetof(oManualMapper::MANUAL_MAP_BUFFER, execution_finished), &is_executed, sizeof(bool), nullptr);

			++time_passed;
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
		} while (!is_executed);

		//obv we do NOT want to deallocate the allocated dll if everything went well 
		Utility::FreeAllocatedMemoryEx(process_handle, {}, allocation_buffer, allocation_functionManualMapShellcode, 
								       allocation_functionMGetProcAddrShellcode, allocation_functionLoadLibraryShellcode, allocation_functionApplyModuleModifications);

		if(is_executed)
		{
			if (additional_flags & MI_MODIFY_MODULE)
			{
				size_t zero_page_size = 1 << 12;
				std::unique_ptr<BYTE[]> zero_page = std::make_unique<BYTE[]>(zero_page_size);

				PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(p_nt_headers);

				auto zero_section = [&zero_page, allocated_dll, &pSection, &zero_page_size, process_handle](const char* section_name)
					{
						if (zero_page_size < pSection->SizeOfRawData)
						{
							zero_page.reset();
							zero_page_size = pSection->SizeOfRawData;
							zero_page = std::make_unique<BYTE[]>(zero_page_size);
						}

						if (!WriteProcessMemory(process_handle, reinterpret_cast<BYTE*>(allocated_dll) + pSection->VirtualAddress, zero_page.get(), pSection->SizeOfRawData, nullptr))
							CONSOLE_LOG_ARGS(true, "Removing Section failed", section_name)
					};

				for (size_t index = 0; index < p_file_header->NumberOfSections; index++, pSection++)
				{
					if ((additional_flags & MI_SECTION_REMOVE_PDATA) && !(additional_flags & MI_EXCEPTION_SUPPORT) && !strcmp(reinterpret_cast<const char*>(pSection->Name), ".pdata"))
					{
						zero_section(reinterpret_cast<const char*>(pSection->Name));
						continue;
					}

					if ((additional_flags & MI_SECTION_REMOVE_RSRC) && !strcmp(reinterpret_cast<const char*>(pSection->Name), ".rsrc"))
					{
						zero_section(reinterpret_cast<const char*>(pSection->Name));
						continue;
					}

					if ((additional_flags & MI_SECTION_REMOVE_RELOC) && !strcmp(reinterpret_cast<const char*>(pSection->Name), ".reloc"))
						zero_section(reinterpret_cast<const char*>(pSection->Name));
				}
			}
		}

		if (!is_inside_hijacked_process)
			process_handle ? CloseHandle(process_handle) : NULL;

		return is_executed;
	}

	bool ManualMapperStub(const wchar_t* dllpath, DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
	{
		return Inject(dllpath, pid, Injection_Method::_ManualMap, exec_method, additional_flags, is_x64);
	}
}

#endif //_WIN64