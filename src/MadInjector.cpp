#include "pch.h"
#include "MadInjector.hpp"
#include "InternalFunctions.h"

#include "x86Invoker/x86Caller.hpp"

MI_API
bool wMadInjector(const wchar_t* dllpath, DWORD pid, DWORD64 injection_flag, DWORD64 execution_flag, DWORD64 additional_flags, bool is_x64)
{
	//TODO code cave scanner so we can use already allocated memory
	//TODO resolve all functions before so we don't have to init them all the time
	//TODO hook scanner
	//TODO debug privilege on entry? or leave as is, privilege can always be adjusted who cares
	//TODO make generic function which tells whenever or not shellcode was executed

	//You might be wondering why am I passing the flags as integers and then converting them to strings which is super bad since string comparisons are slow.
	//The answer is simple when I started this project I didn't even think about using flags in such way therefore I just used strings not thinking about the downsides of it
	//When I added flags most of my stuff already used strings (no im not changing this now idc about this) therefore I just converted the new added flags to strings x)
	//I recommend using flags or something stupid like this *(DWORD64**)"some_string" (this has limits tho especially on wide strings) and then hardcode that value which also would be faster than string comparison.
	//Then again this project was more like of a learning thing for myself. Performance, good error logs, structured maintainable code was not the focus here otherwise the thing would have looked entirely different
	
	//Also caching/init all the function pointers on dll entry would also be a better idea since im currently getting them everytime im calling any of the function that require them which also sucks.

	//not really necessary since it's very unlikely anything will happen to the pointer however there is always that one dude making such scenarios possible
	std::wstring ws_dllpath { dllpath };

#ifdef _WIN64
	if (additional_flags & MI_UNLINK_MODULE)
		return UnlinkModule(ws_dllpath.c_str(), pid, 0, 0, additional_flags, is_x64);
#endif

	const wchar_t* injection_method = Utility::ParseInjectionFlags(injection_flag);
	const wchar_t* exec_method = Utility::ParseExecutionFlags(execution_flag);

	if (!injection_method || !exec_method)
	{
		MessageBoxW(nullptr, L"The Flag you have specified is wrong please keep in mind "
										"that injection_flag and execution_flag can only be one at the same time", L"Error Parsing Flag", MB_OKCANCEL);
		return false;
	}

	if (additional_flags != 0)
	{
		if (additional_flags & MI_CREATE_NEW_CONSOLE && !(additional_flags & MI_USE_EXISTING_CONSOLE))
			Console::CreateNew() = true;
		if (additional_flags & MI_USE_EXISTING_CONSOLE && !(additional_flags & MI_CREATE_NEW_CONSOLE))
			Console::UseExisting() = true;
	}

	if (!(additional_flags & MI_CREATE_NEW_CONSOLE))
		Console::CreateNew() = false;
	if (!(additional_flags & MI_USE_EXISTING_CONSOLE))
		Console::UseExisting() = false;
	
	Console* console = nullptr;
	if( (additional_flags & MI_CREATE_NEW_CONSOLE || additional_flags & MI_USE_EXISTING_CONSOLE ) && !(additional_flags & INSIDE_HIJACKED_HANDLE_PROCESS) ) 
	{
		console = Console::get();
		console ? console->InitConsole() : decltype(std::declval<Console>().InitConsole())();
	}

#if _WIN64
	if(!is_x64)
		return Invoke_x86_Version(ws_dllpath.c_str(), pid, injection_flag, execution_flag, additional_flags, is_x64); //This will only work if your dll and folder(where the dll is located) has no spaces
#endif

	//I am aware that this is the wrong place to do this, the whole symbol thing should go into the dll entry or in a separate function so it's not being invoked all the time
	//however sadly I did not think about any of this up until now where im almost done with the injector and removed my debugging stuff which is also the reason why this was here
	//in the first place. The reason I will keep this here are the following: it does not really affect performance that much at least you should not notice it that much.
	//If I wanted to move this into the dll entry I would have to replace the console log to a file log, it would also require changes for the x86 version and it would cause issues
	//with my handle hijacker which would require me to move this into a separate function call and not inside the dll entry.

	//TODO add some sort of notification when downloading even if debug log is off
	SymbolLoader sLoader{};

	if(is_x64)
	{
		sLoader.Init("ntdll.dll", R"(C:\Windows\System32\ntdll.dll)", is_x64);
		sLoader.Init("kernel32.dll", R"(C:\Windows\System32\kernel32.dll)", is_x64);
	}
	else
	{
		sLoader.Init("ntdll.dll", R"(C:\Windows\SysWOW64\ntdll.dll)", is_x64);
		sLoader.Init("kernel32.dll", R"(C:\Windows\SysWOW64\kernel32.dll)", is_x64);
	}

	static SymbolParser sParser{};

#ifdef _WIN64
	if (additional_flags & MI_UNLOAD_MAPPED_MODULE)
	{
		bool status = UnloadMappedDll(nullptr, pid, nullptr, Utility::ParseExecutionFlags(execution_flag), additional_flags, is_x64);
		console ? console->UnInitConsole() : decltype(std::declval<Console>().UnInitConsole())();
		return status;
	}
#endif

	FunctionInterface function_interface;

	constexpr std::array supported_injection_methods = {
		L"LoadLibrary",
		L"LdrLoadDll",
		L"LdrpLoadDll",
		L"LdrpLoadDllInternal",
		#ifdef _WIN64
		L"ManualMap",
		#endif
	};

	//LoadLibrary
	function_interface.Insert(supported_injection_methods[0], MI_wLoadLibrary);

	//LdrLoadDll
	function_interface.Insert(supported_injection_methods[1], MI_wLdrLoadDll);

	//LdrpLoadDll
	function_interface.Insert(supported_injection_methods[2], MI_wLdrpLoadDll);

	//LdrpLoadDllInternal
	function_interface.Insert(supported_injection_methods[3], MI_wLdrpLoadDllInternal);
#ifdef _WIN64
	//ManualMapper
	function_interface.Insert(supported_injection_methods[4], oManualMapper::ManualMapperStub);
#endif

	bool return_value = false;
	for (const wchar_t* method : supported_injection_methods)
	{
		if(!wcscmp(injection_method, method))
		{
			return_value = function_interface.Invoke<bool>(method, ws_dllpath.c_str(), pid, exec_method, additional_flags, is_x64);
			break;
		}
	}

	console ? console->UnInitConsole() : decltype(std::declval<Console>().UnInitConsole())();

	return return_value;
}

MI_API
bool MadInjector(const char* dllpath, DWORD pid, DWORD64 injection_flag, DWORD64 execution_flag, DWORD64 additional_flags, bool is_x64)
{
	std::vector<std::wstring> strings = Utility::convertToWString(dllpath);
	return wMadInjector(strings.at(0).c_str(), pid, injection_flag, execution_flag, additional_flags, is_x64);
}