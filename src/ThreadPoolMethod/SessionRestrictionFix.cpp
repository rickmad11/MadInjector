#include "pch.h"

#ifdef _WIN64

#include "SessionRestrictionFix.hpp"

#include "ExecutionMethods.hpp"
#include "MadInjector.hpp"
#include "IPC/FileMappingIPC.h"
#include "HandleHijacker/HandleHijacker.hpp"
#include "DataTypesThreadPool.hpp"

namespace oThreadPool
{
	struct ShellcodeData;
}

extern std::uintptr_t GetModuleBaseEx(DWORD pid);

struct IPC_Data
{
	volatile HANDLE job_object_handle = nullptr;

	volatile bool waiting = false;
	volatile bool failure = false;
	volatile bool passed_init = false;
};

namespace SessionRestrictionFix
{
	static void TpJobInsertionEx()
	{
		IPC_Data data{};

		FileMappingIPC SharedMemory(sizeof(data));
		if (SharedMemory.Failed())
			return;

		SharedMemory.MapFile(FILE_MAP_READ | FILE_MAP_WRITE);
		if (SharedMemory.Failed())
			return;

		data.passed_init = true;
		SharedMemory.Write(&data);

		HANDLE job_object_handle = CreateJobObjectW(nullptr, nullptr);

		if (!job_object_handle)
		{
			data.failure = true;
			data.waiting = false;
			SharedMemory.Write(&data);
			return;
		}

		data.job_object_handle = job_object_handle;
		data.waiting = false;
		SharedMemory.Write(&data);

		data.waiting = true;
		while (data.waiting)
			;

		CloseHandle(job_object_handle);
	}

	bool TpJobInsertion(HANDLE const io_completion_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		IPC_Data data {};

		FileMappingIPC SharedMemory(&data, sizeof(IPC_Data));
		if (SharedMemory.Failed())
			return false;

		SharedMemory.MapFile(FILE_MAP_WRITE | FILE_MAP_READ);
		if (SharedMemory.Failed())
			return false;

		PROCESS_INFORMATION pi{};
		STARTUPINFO si{ .cb = sizeof(STARTUPINFO) };

		HANDLE dup_token_handle = nullptr;
		HANDLE token_handle = nullptr;

		(void)OpenProcessToken(process_handle, TOKEN_DUPLICATE, &token_handle);
		(void)DuplicateTokenEx(token_handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, nullptr, SecurityAnonymous, TokenPrimary, &dup_token_handle);

		if (!CreateProcessAsUserW(dup_token_handle, LR"(C:\Windows\System32\conhost.exe)", nullptr, nullptr,
			nullptr, false, 0,
			nullptr, nullptr, &si, &pi))
		{
			CloseHandle(dup_token_handle);
			CloseHandle(token_handle);
			return false;
		}

		auto failure = [&]
			{
				(void)TerminateProcess(pi.hProcess, 0);
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
				CloseHandle(dup_token_handle);
				CloseHandle(token_handle);

				return false;
			};

		std::wstring dllpath = GetModuleFilePath();

		if (dllpath.empty())
			return failure();

		bool ret_status = oCreateThread::Injection(dllpath.c_str(), pi.dwProcessId,
			Injection_Method::_LoadLibrary, L"NtCreateThreadEx",
			MI_THREAD_START_ADDRESS_SPOOF | MI_THREAD_HIDE_FROM_DEBUGGER, true);

		if (!ret_status)
			return failure();

		oThreadPool::ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle
		};

		std::uintptr_t fOffset = reinterpret_cast<std::uintptr_t>(TpJobInsertionEx) - reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"MadInjector.dll"));
		void* pFunction = reinterpret_cast<void*>(GetModuleBaseEx(pi.dwProcessId) + fOffset);

		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		const NtCreateThreadEx pfNtCreateThreadEx = reinterpret_cast<NtCreateThreadEx>(GetProcAddress(ntdll, "NtCreateThreadEx"));

		HANDLE thread_handle = nullptr;

		(void)pfNtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS,
			nullptr, pi.hProcess,
			reinterpret_cast<PUSER_THREAD_START_ROUTINE>(pFunction), nullptr,
			THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0,
			0, 0,
			nullptr);

		if (!thread_handle)
			return failure();

		{
			int time_passed = 0;
			while (!data.passed_init)
			{
				SharedMemory.Read(&data);
				if(time_passed > 50)
					return failure();

				++time_passed;
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}

		data.waiting = true;
		while (data.waiting)
			SharedMemory.Read(&data);

		if(data.failure)
			return failure();

		HANDLE duplicated_job_object_handle = nullptr;
		if (!DuplicateHandle(pi.hProcess, data.job_object_handle, GetCurrentProcess(), &duplicated_job_object_handle, IO_COMPLETION_ALL_ACCESS, false, 0))
			return failure();

		TpAllocJobNotification pfTpAllocJobNotification = reinterpret_cast<TpAllocJobNotification>(GetProcAddress(ntdll, "TpAllocJobNotification"));

		PFULL_TP_JOB full_tp_job = nullptr;
		(void)pfTpAllocJobNotification(&full_tp_job, duplicated_job_object_handle, shellcode.allocated_shellcode, nullptr, nullptr);

		if (!full_tp_job)
		{
			CloseHandle(duplicated_job_object_handle);
			return failure();
		}

		void* allocated_tp_job = VirtualAllocEx(process_handle, nullptr, sizeof(*full_tp_job), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_tp_job)
		{
			CloseHandle(duplicated_job_object_handle);
			return failure();
		}

		if (!WriteProcessMemory(process_handle, allocated_tp_job, full_tp_job, sizeof(*full_tp_job), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_job);
			CloseHandle(duplicated_job_object_handle);
			return failure();
		}

		JOBOBJECT_ASSOCIATE_COMPLETION_PORT completionPort = {};

		if (!SetInformationJobObject(duplicated_job_object_handle, JobObjectAssociateCompletionPortInformation, &completionPort, sizeof(completionPort)))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_job);
			CloseHandle(duplicated_job_object_handle);
			return failure();
		}

		completionPort.CompletionKey = allocated_tp_job;
		completionPort.CompletionPort = io_completion_handle;

		if (!SetInformationJobObject(duplicated_job_object_handle, JobObjectAssociateCompletionPortInformation, &completionPort, sizeof(completionPort)))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_job);
			CloseHandle(duplicated_job_object_handle);
			return failure();
		}

		//you can also use the targets handle however requires additional handle permissions -> PROCESS_SET_QUOTA | PROCESS_TERMINATE;
		if (!AssignProcessToJobObject(duplicated_job_object_handle, GetCurrentProcess()))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_job);
			CloseHandle(duplicated_job_object_handle);
			return failure();
		}

		Sleep(1000);

		data.waiting = false;
		SharedMemory.Write(&data);

		CloseHandle(thread_handle);
		//there is a reason im not calling TpReleaseJobNotification here at all
		//Want to know the reason? checkout my patreon https://patreon.com/rickmad11
		//nah jk I faced crashes lol
		CloseHandle(duplicated_job_object_handle);

		(void)TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		CloseHandle(dup_token_handle);
		CloseHandle(token_handle);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_job);

		return true;
	}
}

#endif