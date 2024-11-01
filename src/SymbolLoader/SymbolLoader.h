#pragma once

//https://llvm.org/docs/PDB/MsfFile.html
//https://gist.github.com/colrdavidson/0cf0b55ed62cc820c34786f658fd4e4b
//https://github.com/microsoft/cci
//https://github.com/jbevain/cecil/tree/master/symbols
//https://bitbucket.org/mambda/pdb-parser/src/master/
//https://www.debuginfo.com/articles/debuginfomatch.html

#define RSDS 0x53445352 // -> 0x53445352 -> "RSDS" -> is a string 
#define GUIDStream 1
//#define DBIStream 3 // Contains structure which tells you what stream symbols are found (offset 20)

//CodeView PDB 7.0 files
//This structure can be easily found, requirements : exe with pdb file (you can make your own real quick)
//then check manual load or collapse the header lol in ida when loading the exe and say yes to load file headers, after that scroll to the very top
//and look for the directories and scroll down until you find Debug Directory then click on dd rva dword_180039400  ; Virtual address and you will notice
//this dd rva asc_18003A794    ; AddressOfRawData double click it and you will see this Debug information (IMAGE_DEBUG_TYPE_CODEVIEW) asc_18003A794   db 'RSDS'
//this is the same structure as below here keep in mind GUID is 16 bytes that's why it looks a bit different in ida
struct PdbInfo
{
	DWORD	Signature;
	GUID	Guid;
	DWORD	Age; 
	char	PdbFileName[1]; //pathname struct hack we need it since pointer to disk string makes no sense
};

struct PDBHeader7
{
	char signature[0x20];
	int page_size;
	int allocation_table_pointer;
	int file_page_count;
	int root_stream_size; //directory size
	int reserved; //zero
	int root_stream_page_number_list_number;
};

struct RootStream7
{
	int num_streams;
	int stream_sizes[ANYSIZE_ARRAY]; //num_streams
};

struct GUID_StreamData
{
	int ver;
	int date;
	int age;
	GUID guid;
};

class SymbolLoader final
{
public:
	explicit SymbolLoader();
	~SymbolLoader() = default;

	SymbolLoader(SymbolLoader const&) = delete;
	SymbolLoader& operator=(SymbolLoader const&) = delete;

	SymbolLoader(SymbolLoader&&) = delete;
	SymbolLoader& operator=(SymbolLoader&&) = delete;

	bool Init(const char* dll_name, const char* path, const bool is_x64);
	bool compareFiles(const std::string& p1, const std::string& p2) const;
	bool verifyPDB(GUID const& guid, std::filesystem::path pdb_path, const char* pdb_name);

private:
	bool symbol_x64_exists = false;
	bool symbol_x86_exists = false;

	bool directory_x64_exists = false;
	bool directory_x86_exists = false;

	std::filesystem::path symbol_path_x86 { "Symbolx86" };
	std::filesystem::path symbol_path_x64 { "Symbolx64" };

	std::filesystem::path dll_path_x64;
	std::filesystem::path dll_path_x86;
};
