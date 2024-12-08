#pragma once

namespace Utility
{
    template<typename... Args>
    std::vector<std::wstring> convertToWString(Args... args) {

        auto _to_wstring = [](const char* arg1) -> std::wstring
            {
                std::wstringstream wss;
                wss << arg1;
                return wss.str();
            };

        std::vector<std::wstring> converted_strings;
        (converted_strings.emplace_back(_to_wstring(args)), ...);

        return converted_strings;
    }

    inline std::wstring Remove_Spaces_From_File_And_Rename(const wchar_t* path)
    {
        std::wstring fixed_name { path };
        size_t pos_of_dll_name = fixed_name.rfind('/');

        std::wstring path_to_file(fixed_name.begin(), fixed_name.begin() + static_cast<size_t>(pos_of_dll_name));

        fixed_name.erase(fixed_name.begin(), fixed_name.begin() + static_cast<size_t>(pos_of_dll_name));
        std::erase(fixed_name, ' ');

        std::wstring new_file_name{ path_to_file + fixed_name };

        std::filesystem::path old_path { path };
        std::filesystem::rename(old_path, new_file_name);

        return new_file_name;
    }

    inline const wchar_t* ParseInjectionFlags(DWORD64 injection_flag)
    {
        enum Flag : DWORD64
        {
            MI_LOAD_LIBRARY            = 1ULL,
            MI_LDR_LOAD_DLL            = 1ULL << 1,
            MI_LDR_P_LOAD_DLL          = 1ULL << 2,
            MI_LDR_P_LOAD_DLL_INTERNAL = 1ULL << 3,
            MI_MANUAL_MAP              = 1ULL << 4
        };

	    switch (injection_flag)
	    {
            case (Flag::MI_LOAD_LIBRARY):
                return L"LoadLibrary";
            case (Flag::MI_LDR_LOAD_DLL):
                return L"LdrLoadDll";
            case (Flag::MI_LDR_P_LOAD_DLL):
                return L"LdrpLoadDll";
            case (Flag::MI_LDR_P_LOAD_DLL_INTERNAL):
                return L"LdrpLoadDllInternal";
            case (Flag::MI_MANUAL_MAP):
                return L"ManualMap";
        
			default:
				return nullptr;
	    }
    }

    inline const wchar_t* ParseExecutionFlags(DWORD64 execution_flag)
    {
        enum Flag : DWORD64
        {
            MI_CREATE_REMOTE_THREAD       = 1ULL,
            MI_NT_CREATE_THREAD_EX        = 1ULL << 1,
            MI_SET_WINDOWS_HOOK           = 1ULL << 2,
            MI_THREAD_HIJACK              = 1ULL << 3,
            MI_QUEUE_USER_APC             = 1ULL << 4,
            MI_KERNEL_CALLBACK_TABLE      = 1ULL << 5,
            MI_VECTORED_EXCEPTION_HANDLER = 1ULL << 7,
            MI_THREAD_POOL_EXECUTION      = 1ULL << 30,
            MI_INSTRUMENTATION_CALLBACK   = 1ULL << 39,
            MI_TLS_CALLBACK_EXECUTION     = 1ULL << 41,
        };

        switch (execution_flag)
        {
        case (Flag::MI_CREATE_REMOTE_THREAD):
            return L"CreateRemoteThread";
        case (Flag::MI_NT_CREATE_THREAD_EX):
            return L"NtCreateThreadEx";
        case (Flag::MI_SET_WINDOWS_HOOK):
            return L"SetWindowsHook";
        case (Flag::MI_THREAD_HIJACK):
            return L"ThreadHijack";
        case (Flag::MI_QUEUE_USER_APC):
            return L"QueueUserAPC";
        case (Flag::MI_KERNEL_CALLBACK_TABLE):
            return L"KernelCallbackTable";
        case (Flag::MI_VECTORED_EXCEPTION_HANDLER):
            return L"VectoredExceptionHandler";
        case (Flag::MI_THREAD_POOL_EXECUTION):
            return L"ThreadPool";
        case (Flag::MI_INSTRUMENTATION_CALLBACK):
            return L"InstrumentationCallback";
        case (Flag::MI_TLS_CALLBACK_EXECUTION):
            return L"TlsCallback";

        default:
            return nullptr;
        }

        return nullptr;
    }

    inline void LoadSymbols(const wchar_t* path)
    {
        static SymbolParser sParser{ path };
    }

    //Honestly a class which keeps track of all the allocs would be better but this was a quicker to write so xD
    template <typename... Args> requires (std::conjunction_v<std::is_pointer<Args>...>)
	void FreeAllocatedMemoryEx(HANDLE process_handle, std::string_view message, Args... args)
    {
        if(!message.empty())
			CONSOLE_LOG_ERROR(message.data())

    	((args ? VirtualFreeEx(process_handle, args, 0, MEM_RELEASE) : NULL), ...);
    }

    struct IMAGE_SECTION {
        void* VirtualAddress;
        DWORD   SizeOfRawData;
        ULONG_PTR size_function;
        bool section_failed;
    };

    inline bool GetSectionInformation(const char* sec_name, IMAGE_SECTION* sec_header) {
        //Update future me here realized this is wrong it should be GetModuleHandleW(L"MadInjector.dll") im walking sections of the process that loaded me xDD holy fuck
		//realizing this after almost finishing the project I don't think its worth using this anymore I used the cool way to get the function size lol
        //my functions using this are mapping the entire section into the target which is fine tho it's just 20-30 bytes more.
        //I could have used this in my manual mapper which would reduce allocation and use of function pointers well it's too late now I will keep my old stuff
        LONG_PTR base_module = reinterpret_cast<LONG_PTR>(GetModuleHandleW(L"MadInjector.dll"));

        //usually will happen with the x86 version bcs im lazy
        if(!base_module)
        {
            sec_header->section_failed = true;
            return false;
        }

        IMAGE_DOS_HEADER* pDH = reinterpret_cast<IMAGE_DOS_HEADER*>(base_module);
        IMAGE_NT_HEADERS* pNTH = reinterpret_cast<IMAGE_NT_HEADERS*>(base_module + pDH->e_lfanew);

        IMAGE_SECTION_HEADER* pFirst_Section = IMAGE_FIRST_SECTION(pNTH);

        for (LONG_PTR index = 0; index < pNTH->FileHeader.NumberOfSections && pFirst_Section; index++, pFirst_Section++) {

            char current_sec_name[IMAGE_SIZEOF_SHORT_NAME];
            memcpy_s(current_sec_name, IMAGE_SIZEOF_SHORT_NAME, &pFirst_Section->Name, IMAGE_SIZEOF_SHORT_NAME);

            if (!memcmp(sec_name, current_sec_name, IMAGE_SIZEOF_SHORT_NAME))
            {
                sec_header->VirtualAddress = reinterpret_cast<void*>(base_module + pFirst_Section->VirtualAddress);
                sec_header->SizeOfRawData = pFirst_Section->SizeOfRawData;
                sec_header->size_function = pFirst_Section->Misc.VirtualSize;
                sec_header->section_failed = false;

                return true;
            }
        }

        sec_header->section_failed = true;
        return false;
    }

    inline std::wstring GetWindowsVersion()
    {
        static NTSTATUS(WINAPI * pfRtlGetVersion) (OSVERSIONINFOEX*) = reinterpret_cast<decltype(pfRtlGetVersion)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));

        OSVERSIONINFOEX osvi {.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX) };

	    if(!pfRtlGetVersion(&osvi))
	    {
            if (osvi.dwBuildNumber >= 26100)
                return L"24H2";

	    	else if (osvi.dwBuildNumber >= 22631)
                return L"23H2";
	    }

        return { L"Unknown" };
    }
}

