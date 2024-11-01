#include "pch.h"
#include "FileMappingIPC.h"

/// @param size_of_data size of the structure holding your data in bytes
FileMappingIPC::FileMappingIPC(const DWORD64 size_of_data)
{
	m_mapped_file_handle = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, false, L"Global\\MadInjectorObjectIPC2");

	if (!m_mapped_file_handle)
		m_internal_error = true;

	m_size_of_data = static_cast<size_t>(size_of_data);
}

/// use this constructor when you are the one writing/sending information
/// @param pMappedData pointer to a structure holding your data
/// @param size_of_data size of the structure holding your data in bytes
FileMappingIPC::FileMappingIPC(void* const pMappedData, const DWORD64 size_of_data)
{
	SetLastError(0);

	m_mapped_file_handle = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
				       PAGE_READWRITE | SEC_COMMIT, size_of_data >> 32,
				       size_of_data & 0xFFFFFFFF, L"Global\\MadInjectorObjectIPC2");

	//This is required however this erases every security for our object and is available for everyone. But it's the only way I can think of to make this work
	//This might not affect you, im having this issue since I am creating the Mapped File inside a session 0 process
	//if the initial file mapping was created by a lower privileged process then the higher privileged process could just normally use the file mapping without any additional steps
	SetSecurityInfo(m_mapped_file_handle, SE_KERNEL_OBJECT,
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		nullptr, nullptr, nullptr, nullptr);

	if (GetLastError() == ERROR_ALREADY_EXISTS)
		m_internal_error = true;

	if (!m_mapped_file_handle)
		m_internal_error = true;

	m_size_of_data = static_cast<size_t>(size_of_data);
	//m_pMappedData = pMappedData;
	//m_copy_MappedData = std::make_unique_for_overwrite<BYTE[]>(static_cast<size_t>(m_size_of_data));
	//memcpy_s(m_copy_MappedData.get(), m_size_of_data, m_pMappedData, m_size_of_data);
}

/// @return when it returns true something went wrong in the last call.
bool FileMappingIPC::Failed()
{
	bool tmp = m_internal_error;
	m_internal_error = false;
	return tmp;
}

/// Invoke this when Failed() returns true and UnMapFile() basically what my destructor does (! only do this when at the construction Failed() returns true)
void FileMappingIPC::Close()
{
	m_mapped_file_handle ? CloseHandle(m_mapped_file_handle) : NULL;
	m_mapped_file_handle = nullptr;
}

/// @param offset basically the index in bytes where you want to start reading your stuff I won't need this, but I did it anyway
void FileMappingIPC::AdjustMappedOffset(DWORD64 offset)
{
	if (offset >= m_size_of_data)
	{
		m_internal_error = true;
		return;
	}

	m_offset = offset;

	if (m_dwDesiredAccess == -1)
		return;

	m_pMappedFileInMemory = MapViewOfFile(m_mapped_file_handle, m_dwDesiredAccess, offset >> 32, offset & 0xFFFFFFFF, 0);

	if (!m_pMappedFileInMemory)
		m_internal_error = true;
}

//Exception handling is very recommended however idc
void FileMappingIPC::Read(void* const pData) const
{
	if (m_pMappedFileInMemory)
		memcpy_s(pData, m_size_of_data - m_offset, static_cast<BYTE*>(m_pMappedFileInMemory) + m_offset, m_size_of_data - m_offset);
}

//Exception handling is very recommended however idc
void FileMappingIPC::Write(void const* const pData) const
{
	if(m_pMappedFileInMemory)
		memcpy_s(static_cast<BYTE*>(m_pMappedFileInMemory) + m_offset, m_size_of_data - m_offset, pData, m_size_of_data - m_offset);
}

FileMappingIPC::~FileMappingIPC()
{
	UnMapFile();
	Close();
}

/// @param dwDesiredAccess this can be one of the following: FILE_MAP_READ FILE_MAP_WRITE FILE_MAP_ALL_ACCESS
void FileMappingIPC::MapFile(DWORD dwDesiredAccess)
{
	m_dwDesiredAccess = dwDesiredAccess;

	m_pBaseAddressFileInMemory = MapViewOfFile(m_mapped_file_handle, dwDesiredAccess, 0, 0, 0);

	if (!m_pBaseAddressFileInMemory)
		m_internal_error = true;

	if(!m_internal_error)
		m_pMappedFileInMemory = m_pBaseAddressFileInMemory;
}

void FileMappingIPC::UnMapFile()
{
	if(m_pBaseAddressFileInMemory)
	{
		UnmapViewOfFile(m_pBaseAddressFileInMemory);
		m_pBaseAddressFileInMemory = nullptr;
	}
}

