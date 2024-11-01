#include "pch.h"
#include "SymbolParser.h"

SymbolParser::SymbolParser()
{
	CONSOLE_LOG("Init Smybol Parser...")

	own_pseudo_handle = GetCurrentProcess();
	SetLastError(ERROR_SUCCESS); //pseudo handle is -1 i just want to clean the error codes

	DWORD own_proc_id = GetProcessId(own_pseudo_handle);

	handle_to_own_process = OpenProcess(PROCESS_ALL_ACCESS, false, own_proc_id);

	if (!handle_to_own_process)
		handle_to_own_process = own_pseudo_handle;

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS);

#if _WIN64
	if(!SymInitializeW(handle_to_own_process, L"Symbolx64", true))
	{
		CONSOLE_LOG_ERROR("SymInitializeW failed")
	}
#else
	if(!SymInitializeW(handle_to_own_process, L"Symbolx86", true))
	{
		CONSOLE_LOG_ERROR("SymInitializeW failed")
	}
#endif

	CONSOLE_LOG("Symbol Parser ready!")
}

SymbolParser::SymbolParser(std::filesystem::path path)
{
	CONSOLE_LOG("Init Smybol Parser...")

	own_pseudo_handle = GetCurrentProcess();
	SetLastError(ERROR_SUCCESS); //pseudo handle is -1 i just want to clean the error codes

	DWORD own_proc_id = GetProcessId(own_pseudo_handle);

	handle_to_own_process = OpenProcess(PROCESS_ALL_ACCESS, false, own_proc_id);

	if (!handle_to_own_process)
		handle_to_own_process = own_pseudo_handle;

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS);

#if _WIN64
	if (!SymInitializeW(handle_to_own_process, path.c_str(), true))
	{
		CONSOLE_LOG_ERROR("SymInitializeW failed")
	}
#else
	if (!SymInitializeW(handle_to_own_process, L"Symbolx86", true))
	{
		CONSOLE_LOG_ERROR("SymInitializeW failed")
	}
#endif

	CONSOLE_LOG("Symbol Parser ready!")

}

SymbolParser::~SymbolParser()
{
	SymCleanup(handle_to_own_process);
	CloseHandle(handle_to_own_process);
}