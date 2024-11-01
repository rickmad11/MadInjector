#include "pch.h"
#include "SymbolLoader.h"

#include "DownloadManager/DownloadCallback.h"

SymbolLoader::SymbolLoader()
{
	CONSOLE_LOG("Checking if Symbol Path and directory exists...")

	directory_x86_exists = std::filesystem::exists(symbol_path_x86);

	if(!directory_x86_exists)
	{
		CONSOLE_LOG_ERROR("Symbolx86 directory does not exist creating new one")
		if (std::filesystem::create_directory(symbol_path_x86))
		{
			directory_x86_exists = true;
			CONSOLE_LOG("successfully created directory for x86")
		}
		else
		{
			directory_x86_exists = false;
			CONSOLE_LOG_ERROR("Failed to create new directory for x86")
		}
	}

	directory_x64_exists = std::filesystem::exists(symbol_path_x64);

	if (!directory_x64_exists)
	{
		CONSOLE_LOG_ERROR("Symbolx64 directory does not exist creating new one")
			if (std::filesystem::create_directory(symbol_path_x64))
			{
				directory_x64_exists = true;
				CONSOLE_LOG("successfully created directory for x64")
			}
			else
			{
				directory_x64_exists = false;
				CONSOLE_LOG_ERROR("Failed to create new directory for x64")
			}
	}

	CONSOLE_LOG("Finished Checking Symbol Paths and directories!")
}

bool SymbolLoader::Init(const char* dll_name, const char* path , const bool is_x64)
{
	CONSOLE_LOG("Loading Symbols...")

	dll_path_x64 = symbol_path_x64 / dll_name;
	dll_path_x86 = symbol_path_x86/ dll_name;

	if(!std::filesystem::exists(is_x64 ? dll_path_x64 : dll_path_x86))
		std::filesystem::copy(path, is_x64 ? symbol_path_x64 : symbol_path_x86);

	if (!compareFiles(is_x64 ? dll_path_x64.generic_string() : dll_path_x86.generic_string(), path))
	{
		CONSOLE_LOG("File is outdated updating file...")
		std::filesystem::remove(is_x64 ? dll_path_x64 : dll_path_x86);
		std::filesystem::copy(path, is_x64 ? symbol_path_x64 : symbol_path_x86);
		CONSOLE_LOG("File has been updated!")
	}

	std::ifstream system32_dll(is_x64 ? dll_path_x64 : dll_path_x86, std::ios_base::binary);

	if(system32_dll.fail())
	{
		CONSOLE_LOG_ERROR(("Failed opening " + std::string(dll_name)).c_str())
		return false;
	}

	std::uint64_t file_size = std::filesystem::file_size(is_x64 ? dll_path_x64 : dll_path_x86);

	CONSOLE_LOG("Allocating buffer for pe_header")

	std::unique_ptr<BYTE[]> pe_buffer = std::make_unique<BYTE[]>(file_size);
	
	if(!pe_buffer)
	{
		CONSOLE_LOG_ERROR("Allocation failed! holy fuck if this actly happens it kinda would be cool")
		system32_dll.close();
		return false;
	}
	CONSOLE_LOG("Allocation successful BYTES:", file_size)

	system32_dll.read(reinterpret_cast<char*>(pe_buffer.get()), static_cast<std::streamsize>(file_size));
	system32_dll.close();

	PIMAGE_DOS_HEADER pDOS_header		= reinterpret_cast<PIMAGE_DOS_HEADER>(pe_buffer.get());
	PIMAGE_NT_HEADERS pNT_header		= reinterpret_cast<PIMAGE_NT_HEADERS>(pe_buffer.get() + pDOS_header->e_lfanew);
	PIMAGE_FILE_HEADER pFILE_header		= &pNT_header->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOPT_header	= &pNT_header->OptionalHeader;

	std::uint64_t imagesize = pOPT_header->SizeOfImage;

	BYTE* const pLocalImageBase = static_cast<BYTE* const>(VirtualAlloc(nullptr, imagesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pLocalImageBase)
	{
		CONSOLE_LOG_ERROR("Allocating memory failed!")
		return false;
	}

	CONSOLE_LOG("Allocated memory at:", pLocalImageBase)

	memcpy(pLocalImageBase, pe_buffer.get(), pOPT_header->SizeOfHeaders);

	PIMAGE_SECTION_HEADER pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT_header);
	for (size_t i = 0; i < pFILE_header->NumberOfSections && pCurrentSectionHeader; pCurrentSectionHeader++ , i++)
	{
		if (pCurrentSectionHeader->SizeOfRawData > 0)
			memcpy(pLocalImageBase + pCurrentSectionHeader->VirtualAddress, pe_buffer.get() + pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
	}

	PIMAGE_DATA_DIRECTORY pData_dir	= &pOPT_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

	if(!pData_dir->Size)
	{
		CONSOLE_LOG_ERROR("PIMAGE_DATA_DIRECTORY is empty")
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		return false;
	}

	PIMAGE_DEBUG_DIRECTORY pDebug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(pLocalImageBase + pData_dir->VirtualAddress);

	for (; pDebug_dir && pDebug_dir->SizeOfData; pDebug_dir++)
	{
		//usually the first entry but who knows
		if (IMAGE_DEBUG_TYPE_CODEVIEW == pDebug_dir->Type)
			break;
	}

	if(pDebug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
	{
		CONSOLE_LOG_ERROR("no IMAGE_DEBUG_TYPE_CODEVIEW found")
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		return false;
	}

	PdbInfo* pDBG_info = reinterpret_cast<PdbInfo*>(pLocalImageBase + pDebug_dir->AddressOfRawData);

	if(verifyPDB(pDBG_info->Guid, (is_x64 ? symbol_path_x64 : symbol_path_x86), pDBG_info->PdbFileName))
	{
		CONSOLE_LOG("PDB already exists skipping download")
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		return false;
	}

	//RSDS meaning CodeView format for PDB 7.0 files
	if(pDBG_info->Signature != RSDS)
	{
		CONSOLE_LOG_ERROR("pDBG_info is wrong")
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		return false;
	}

	std::wstring pdb_name{};
	{
		std::string temp_pdb_name(pDBG_info->PdbFileName);
		pdb_name = std::wstring(temp_pdb_name.begin(), temp_pdb_name.end());
	}

	wchar_t w_GUID[MAX_PATH] {};

	if(!StringFromGUID2(pDBG_info->Guid, w_GUID, MAX_PATH))
	{
		CONSOLE_LOG_ERROR("GUID conversion failed")
		VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
		return false;
	}

	//we could also do it the stl way however I basically pasted the gh injector way xD, this is necessary since we don't want any other special characters for instance - or {}...
	std::wstring string_guid (w_GUID);
	{
		std::wstring temp_string{};
		for (auto const& ch : string_guid)
		{
			if ( ch >= '0' && ch <= '9' || (ch >= 'A' && ch <= 'F' ) || (ch >= 'a' && ch <= 'f') )
				temp_string += ch;
		}
		string_guid = temp_string;
	}

	std::wstring pdb_download_url =
	{
		LR"(https://msdl.microsoft.com/download/symbols/)" +
		pdb_name +
		L'/' +
		string_guid +
		std::to_wstring(pDBG_info->Age) +
		L'/' +
		pdb_name
	};

	CONSOLE_LOG("Checking Connection...")

	float start_tick = clock() * 0.001f;
	while (!InternetCheckConnectionW(LR"(https://msdl.microsoft.com)", FLAG_ICC_FORCE_CONNECTION, NULL))
	{
		float current_tick = clock() * 0.001f;
		if (current_tick - start_tick >= 20.f)
		{
			CONSOLE_LOG_ERROR("exceeded wait time for a internet connection")
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
			return false;
		}

		if (GetLastError() == ERROR_INTERNET_CANNOT_CONNECT)
		{
			CONSOLE_LOG_ERROR("No Internet Connection found")
			VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
			return false;
		}
	}

	CONSOLE_LOG(L"Downloading: " + pdb_download_url)

	DownloadCallback download_manager;
	std::filesystem::path selected_path = is_x64 ? symbol_path_x64 : symbol_path_x86;
	URLDownloadToFileW(nullptr, pdb_download_url.c_str(), (selected_path / pdb_name).c_str(), NULL, &download_manager);

	std::cout << '\n'; // because of our great download manager
	CONSOLE_LOG("Finished Loading Symbols!")

	VirtualFree(pLocalImageBase, 0, MEM_RELEASE);
	return true;
}

//https://stackoverflow.com/questions/6163611/compare-two-files
bool SymbolLoader::compareFiles(const std::string& p1, const std::string& p2) const {
	std::ifstream f1(p1, std::ifstream::binary | std::ifstream::ate);
	std::ifstream f2(p2, std::ifstream::binary | std::ifstream::ate);

	if (f1.fail() || f2.fail())
		return false; 

	if (f1.tellg() != f2.tellg())
		return false; 

	f1.seekg(0, std::ifstream::beg);
	f2.seekg(0, std::ifstream::beg);
	return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
		std::istreambuf_iterator<char>(),
		std::istreambuf_iterator<char>(f2.rdbuf()));
}

bool SymbolLoader::verifyPDB(GUID const& guid, std::filesystem::path pdb_path, const char* pdb_name)
{
	CONSOLE_LOG("verifying PDB file...")

	std::ifstream file(pdb_path / pdb_name, std::ios::binary);

	if (file.fail())
	{
		CONSOLE_LOG_ERROR("PDB does not exist downloading pdb file...")		
		return false;
	}

	unsigned int file_size = static_cast<unsigned int>(std::filesystem::file_size(pdb_path / pdb_name));

	std::unique_ptr<BYTE[]> file_buffer = std::make_unique<BYTE[]>(file_size);

	if (!file_buffer)
	{
		CONSOLE_LOG_ERROR("Allocation for the file failed")		
		return false;
	}

	file.read(reinterpret_cast<char*>(file_buffer.get()), static_cast<std::streamsize>(file_size));
	file.close();

	PDBHeader7* pPDBHeader = reinterpret_cast<PDBHeader7*>(file_buffer.get());

	if (memcmp(pPDBHeader->signature, "Microsoft C/C++ MSF 7.00\r\n\x1A""DS\0\0\0", sizeof(PDBHeader7::signature)))
	{
		CONSOLE_LOG_ERROR("not a valid PDB file")
		return false;
	}

	DWORD const* const pRootPageNumber = reinterpret_cast<DWORD const* const>(file_buffer.get() + (pPDBHeader->root_stream_page_number_list_number * pPDBHeader->page_size));

	if (!pRootPageNumber)
	{
		CONSOLE_LOG_ERROR("pRootPageNumber is not valid")
		return false;
	}

	RootStream7* pRootStream = reinterpret_cast<RootStream7*>(file_buffer.get() + (*pRootPageNumber * pPDBHeader->page_size));

	int pdb_info_page_index = -1;
	for (int i = 0, current_page_number = 0; i != pRootStream->num_streams; ++i)
	{
		int current_size = pRootStream->stream_sizes[i] == MAXUINT ? 0 : pRootStream->stream_sizes[i];

		int current_page_count = (current_size + pPDBHeader->page_size - 1) / pPDBHeader->page_size;

		if(i == GUIDStream && current_page_count > 0)
		{
			pdb_info_page_index = pRootStream->stream_sizes[pRootStream->num_streams + current_page_number];
			break;
		}

		current_page_number += current_page_count;
	}

	if(pdb_info_page_index == -1)
	{
		return false;
	}

	GUID_StreamData* stream_data = reinterpret_cast<GUID_StreamData*>(file_buffer.get() + static_cast<size_t>(pdb_info_page_index) * pPDBHeader->page_size);

	if(memcmp(&stream_data->guid, &guid, sizeof(GUID)))
	{
		CONSOLE_LOG_ERROR("pdb file is not up to date")
		return false;
	}

	CONSOLE_LOG("PDB file is up to date!")
	return true;
}

