#include <clocale>
#include <iostream>
#include <string>
#include <windows.h>

bool wMadInjector(const wchar_t* dllpath, DWORD pid, DWORD64 injection_flag, DWORD64 execution_flag, DWORD64 additional_flags, bool is_x64 = true);

//This will only work if your dll has no spaces
int wmain(int argc, wchar_t** argv)
{
	if (argc < 5)
		return false;

	(void)std::setlocale(LC_ALL, "");

	HMODULE dll = LoadLibraryA("MadInjectorX86.dll");
	
	decltype(wMadInjector)* MadInjectorEntry = reinterpret_cast<decltype(wMadInjector)*>(GetProcAddress(dll, "wMadInjector"));
	return MadInjectorEntry(argv[0], std::stoul(argv[1]), std::stoull(argv[2]),
							std::stoull(argv[3]), std::stoull(argv[4]), std::stoi(argv[5]));
}