#pragma once

class FileMappingIPC final
{
public:
	FileMappingIPC(const DWORD64 size_of_data);
	FileMappingIPC(void* const pMappedData, const DWORD64 size_of_data);

	FileMappingIPC(FileMappingIPC const&) = delete;
	FileMappingIPC& operator=(FileMappingIPC const&) = delete;

	FileMappingIPC(FileMappingIPC&&) = delete;
	FileMappingIPC& operator=(FileMappingIPC&&) = delete;

	~FileMappingIPC();

public:
	void MapFile(DWORD dwDesiredAccess);
	void UnMapFile();

public:
	bool Failed();
	void Close();

public:
	void AdjustMappedOffset(DWORD64 offset);
	void Read(void* const pData) const;
	void Write(void const* const pData) const;

private:
	bool m_internal_error = false;
	HANDLE m_mapped_file_handle = nullptr;
	//void* m_pMappedData = nullptr;
	void* m_pMappedFileInMemory = nullptr;
	void* m_pBaseAddressFileInMemory = nullptr;
	size_t m_size_of_data = 0;
	//std::unique_ptr<BYTE[]> m_copy_MappedData = nullptr;
	std::int64_t m_dwDesiredAccess = -1;
	DWORD m_offset = 0;
};

