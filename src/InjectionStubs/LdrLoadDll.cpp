#include "pch.h"

#include "ExecutionMethods.hpp"
#include "InternalFunctions.h"

bool MI_wLdrLoadDll(const wchar_t* dllpath, DWORD pid, const wchar_t* exec_method, DWORD64 additional_flags, bool is_x64)
{

	if (!wcscmp(exec_method, L"CreateRemoteThread") || !wcscmp(exec_method, L"NtCreateThreadEx"))
		return oCreateThread::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

	if (!wcscmp(exec_method, L"SetWindowsHook"))
		return oSetWindowsHook::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

	if (!wcscmp(exec_method, L"ThreadHijack"))
		return oThreadHijack::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

	if (!wcscmp(exec_method, L"QueueUserAPC"))
		return oQueueUserAPC::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

	if (!wcscmp(exec_method, L"KernelCallbackTable"))
		return oKernelCallbackTable::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

#ifdef _WIN64
	if (!wcscmp(exec_method, L"VectoredExceptionHandler"))
		return oVectoredExceptionHandler::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

	if (!wcscmp(exec_method, L"ThreadPool"))
		return oThreadPool::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

	if (!wcscmp(exec_method, L"InstrumentationCallback"))
		return oInstrumentationCallback::Inject(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);

	if (!wcscmp(exec_method, L"TlsCallback"))
		return oTlsCallback::Injection(dllpath, pid, Injection_Method::_LdrLoadDll, exec_method, additional_flags, is_x64);
#endif

	return false;
}
