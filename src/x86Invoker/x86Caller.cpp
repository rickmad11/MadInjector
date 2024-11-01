#include "pch.h"
#include "x86Caller.hpp"

bool Invoke_x86_Version(const wchar_t* dllpath, DWORD pid, DWORD64 injection_flag, DWORD64 execution_flag, DWORD64 additional_flags, bool is_x64)
{
	[[maybe_unused]] std::wstring new_dll_path {}; // only if condition is true and user clicks yes
	if (std::wstring(dllpath).contains(' '))
	{
		int return_type = MessageBoxW(nullptr, L"DllPath or your Folders contain spaces,"
		" please remove all spaces in your dll name or Folders since the x86 injector requires this! "
		"press yes to remove all spaces from the dll, keep in mind this will not fix the Folder issue", L"Error Injecting", MB_YESNO);

		if (return_type == IDYES)
		{
			dllpath = (new_dll_path = Utility::Remove_Spaces_From_File_And_Rename(dllpath)).c_str();
		}
		else if (return_type == IDNO)
			return false;
	}

	std::wostringstream commandline;
	commandline 
	<< dllpath << L" "
	<< pid << L" "
	<< injection_flag << L" "
	<< execution_flag << L" "
	<< additional_flags << L" "
	<< is_x64;

	std::wstring commandlineStr = commandline.str();

	STARTUPINFOW si = {.cb = sizeof(si)};
	PROCESS_INFORMATION pi {};

	//This will only work if your dll has no spaces
	if (CreateProcessW(LR"(MadInjectorX86.exe)", commandlineStr.data(),
	                   nullptr, nullptr,
	                   FALSE,
	                   CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
	                   nullptr, nullptr,
	                   &si, &pi))
	{
		WaitForSingleObject(pi.hProcess, INFINITE);

		DWORD exit_code = 0;
		GetExitCodeProcess(pi.hProcess, &exit_code);

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		return static_cast<bool>(exit_code);
	}
	
	return false;
}
