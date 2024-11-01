#include "pch.h"

#ifdef _WIN64

#include "InternalFunctions.h"
#include "MadInjector.hpp"
#include "DataTypesThreadPool.hpp"
#include "SessionRestrictionFix.hpp"

namespace oThreadPool
{
	ShellcodeData::ShellcodeData(void* pFunc, void* pArgs, HANDLE process_handle) : pFunc(pFunc), pArgs(pArgs), process_handle(process_handle)
	{
		reinterpret_cast<ShellcodeData*>(reinterpret_cast<BYTE*>(shellcode) + 5)->pArgs = pArgs;
		reinterpret_cast<ShellcodeData*>(reinterpret_cast<BYTE*>(shellcode) + 5)->pFunc = pFunc;

		allocated_shellcode = VirtualAllocEx(process_handle, nullptr, sizeof(std::declval<ShellcodeData>().shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocated_shellcode)
		{
			internal_error = true;
			return;
		}

		if (!WriteProcessMemory(process_handle, allocated_shellcode, shellcode, sizeof(std::declval<ShellcodeData>().shellcode), nullptr))
		{
			CONSOLE_LOG_ERROR("failed Writing memory for shellcode")
				internal_error = true;
			return;
		}
	}

	ShellcodeData::ShellcodeData(void* pFunc, void* pArgs, HANDLE process_handle, DWORD64 fSize, void* pfAny) : pFunc(pFunc), pArgs(pArgs), process_handle(process_handle), function_size(fSize), pfAny(pfAny)
	{
		has_function = true;

		allocated_args = VirtualAllocEx(process_handle, nullptr, sizeof(POOL_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_args)
		{
			CONSOLE_LOG_ERROR("failed allocating memory for arguments")
				internal_error = true;
			return;
		}

		pool_data.pFunction = pFunc;
		pool_data.pArgs = pArgs;
		pool_data.pfGetCurrentThread = GetCurrentThread;
		pool_data.pfSuspendThread = SuspendThread;
		pool_data.pfGetCurrentThreadId = GetCurrentThreadId;

		if (!WriteProcessMemory(process_handle, allocated_args, &pool_data, sizeof(POOL_DATA), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing pool data", allocated_args);
			internal_error = true;
			return;
		}

		allocated_function = VirtualAllocEx(process_handle, nullptr, function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocated_function)
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing pool data", allocated_args);
			internal_error = true;
			return;
		}

		if (!WriteProcessMemory(process_handle, allocated_function, pfAny, function_size, nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing pool data", allocated_args, allocated_function);
			internal_error = true;
			return;
		}

		*const_cast<void**>(&reinterpret_cast<ShellcodeData*>(reinterpret_cast<BYTE*>(shellcode) + 5)->pArgs) = allocated_args;
		*const_cast<void**>(&reinterpret_cast<ShellcodeData*>(reinterpret_cast<BYTE*>(shellcode) + 5)->pFunc) = allocated_function;

		allocated_shellcode = VirtualAllocEx(process_handle, nullptr, sizeof(std::declval<ShellcodeData>().shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);

		if (!allocated_shellcode)
		{
			CONSOLE_LOG_ERROR("Allocation failed")
				internal_error = true;
			return;
		}

		if (!WriteProcessMemory(process_handle, allocated_shellcode, shellcode, sizeof(std::declval<ShellcodeData>().shellcode), nullptr))
		{
			CONSOLE_LOG_ERROR("WriteProcessMemory failed")
				internal_error = true;
			return;
		}
	}
}

#pragma code_seg (push)
#pragma code_seg(".xxx")
#pragma optimize("", off)

struct POOL_DATA
{
	void* pFunction										= nullptr;
	void* pArgs											= nullptr;
	decltype(SuspendThread)* pfSuspendThread			= nullptr;
	decltype(GetCurrentThread)* pfGetCurrentThread		= nullptr;
	decltype(GetCurrentThreadId)* pfGetCurrentThreadId  = nullptr;
	DWORD thread_id = 0;
};

namespace 
{
	void __stdcall ShellcodeForwarder(POOL_DATA* buffer)
	{
		//we don't need to relink the list or do anything with it the process will revert our changes on its own
		//HOWEVER we do need to make this thread stop execution our allocated memory bcs obv im going to deallocate it after execution

		reinterpret_cast<void(__stdcall*)(void*)>(buffer->pFunction)(buffer->pArgs);

		//why all of this trash? well bcs we crash at TpSimpleTryPost and idk why nor will I look for a fix
		buffer->thread_id = buffer->pfGetCurrentThreadId();
		buffer->pfSuspendThread(buffer->pfGetCurrentThread());

		//this solution sucks since its eating cpu for no reason and needs the function memory to be allocated the entire time
		//while (true)
		//	;
	}

	void Dummy() { std::cout << "yo"; };
}

#pragma optimize("", on)
#pragma code_seg (pop)

namespace oThreadPool
{
	HANDLE GetHandleOfType(const wchar_t* handle_type, DWORD dwDesiredAccess, HANDLE const process_handle, DWORD pid)
	{
		HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");

		NtQueryInformationProcess pfNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess>(GetProcAddress(ntdll_module, "NtQueryInformationProcess"));
		NtQueryObject pfNtQueryObject						  = reinterpret_cast<NtQueryObject>(GetProcAddress(ntdll_module, "NtQueryObject"));

		ULONG allocation_size = 1 << 12;
		std::unique_ptr<BYTE[]> buffer_phi = std::make_unique_for_overwrite<BYTE[]>(allocation_size);
		do
		{
			ULONG buffer_size_required = 0;
			NTSTATUS status = pfNtQueryInformationProcess(process_handle, PROCESSINFOCLASS::ProcessHandleInformation, buffer_phi.get(), allocation_size, &buffer_size_required);

			if(status == STATUS_INFO_LENGTH_MISMATCH)
			{
				buffer_phi.reset();
				allocation_size = buffer_size_required;
				buffer_phi = std::make_unique_for_overwrite<BYTE[]>(allocation_size);
				continue;
			}

			if(status < 0 )
			{
				CONSOLE_LOG_ERROR("NtQueryInformationProcess failed")
				return nullptr;
			}

			break;
		}
		while (true);

		HANDLE process_handle_dup = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
		//a better approach would be to check STATUS_INFO_LENGTH_MISMATCH however the size here is usually between 120 and 200, so it should work most of the time if not always
		std::unique_ptr<BYTE[]> buffer_oti = std::make_unique_for_overwrite<BYTE[]>(1 << 12);

		PPROCESS_HANDLE_SNAPSHOT_INFORMATION pphi = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(buffer_phi.get());
		for (size_t i = 0; i < pphi->NumberOfHandles; i++)
		{
			HANDLE duplicated_handle = nullptr;
			if(!DuplicateHandle(process_handle_dup, pphi->Handles[i].HandleValue, GetCurrentProcess(), &duplicated_handle, dwDesiredAccess, false, 0))
			{
				CloseHandle(duplicated_handle);
				continue;
			}

			pfNtQueryObject(duplicated_handle, OBJECT_INFORMATION_CLASS::ObjectTypeInformation, buffer_oti.get(), 1 << 12, nullptr);
			POBJECT_TYPE_INFORMATION poti = {reinterpret_cast<POBJECT_TYPE_INFORMATION>(buffer_oti.get())};

			const std::wstring handle_type_name = { poti->TypeName.Buffer, poti->TypeName.Length / sizeof(wchar_t) };
			if(handle_type_name == handle_type)
			{
				CONSOLE_LOG_ARGS(false, "Handle of Type:", handle_type, "found!", pphi->Handles[i].HandleValue)
				CloseHandle(process_handle_dup);
				return duplicated_handle;
			}

			memset(buffer_oti.get(), 0, 1 << 12);
			CloseHandle(duplicated_handle);
		}

		CloseHandle(process_handle_dup);
		return nullptr;
	}

	//Will only work once since TppWorkerThread will not be invoked afterward anymore. I honestly don't know how to fix this, I would guess invoking the original behaviour of the function so the thread pool thread
	//gets properly initialized would fix that issue but then again I am not sure and I did not test this since it would require a bit more code and time, probably as well hours of reversing.
	bool WorkerFactoryThreadCreation(HANDLE const worker_factory_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");
		NtQueryInformationWorkerFactory pfNtQueryInformationWorkerFactory = reinterpret_cast<NtQueryInformationWorkerFactory>(GetProcAddress(ntdll_module, "NtQueryInformationWorkerFactory"));

		WORKER_FACTORY_BASIC_INFORMATION wfbi {};
		(void)pfNtQueryInformationWorkerFactory(worker_factory_handle, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi), nullptr);
		
		ShellcodeData shellcode {};

		reinterpret_cast<ShellcodeData*>(reinterpret_cast<BYTE*>(shellcode.shellcode) + 5)->pArgs = allocated_memory_thread_data;
		reinterpret_cast<ShellcodeData*>(reinterpret_cast<BYTE*>(shellcode.shellcode) + 5)->pFunc = allocated_memory_code;

		BYTE original_instructions[sizeof(std::declval<ShellcodeData>().shellcode)] = { };
		if (!ReadProcessMemory(process_handle, wfbi.StartRoutine, original_instructions, sizeof(std::declval<ShellcodeData>().shellcode), nullptr))
			return false;

		DWORD oPageProtection;
		if (!VirtualProtectEx(process_handle, wfbi.StartRoutine, sizeof(std::declval<ShellcodeData>().shellcode), PAGE_READWRITE, &oPageProtection))
			return false;

		//wfbi.StartRoutine is a function not a pointer luckily the function is huge and our shellcode fits just fine
		//the downside here is obv we are patching .text section
		//wfbi.StartRoutine is the function -> TppWorkerThread 
		if(!WriteProcessMemory(process_handle, wfbi.StartRoutine, shellcode.shellcode, sizeof(std::declval<ShellcodeData>().shellcode), nullptr))
			return false;

		if(!VirtualProtectEx(process_handle, wfbi.StartRoutine, sizeof(std::declval<ShellcodeData>().shellcode), oPageProtection, &oPageProtection))
		{
			(void)VirtualProtectEx(process_handle, wfbi.StartRoutine, sizeof(std::declval<ShellcodeData>().shellcode), oPageProtection, &oPageProtection);
			return false;
		}

		NtSetInformationWorkerFactory pfNtSetInformationWorkerFactory = reinterpret_cast<NtSetInformationWorkerFactory>(GetProcAddress(ntdll_module, "NtSetInformationWorkerFactory"));

		//wfbi.TotalWorkerCount will not simply increment again when invoked multiple times, issue is unknown to me probably has something to do that we skipped the entire entry point of the thread pool thread
		ULONG new_thread_minimum = wfbi.TotalWorkerCount + 1;
		(void)pfNtSetInformationWorkerFactory(worker_factory_handle, WorkerFactoryThreadMinimum, &new_thread_minimum, sizeof(ULONG));

		//yeah this is bad I know, it would be better to check if executed but honestly idc
		Sleep(1000);

		if (!VirtualProtectEx(process_handle, wfbi.StartRoutine, sizeof(std::declval<ShellcodeData>().shellcode), PAGE_READWRITE, &oPageProtection))
			return false;

		if(!WriteProcessMemory(process_handle, wfbi.StartRoutine, original_instructions, sizeof(std::declval<ShellcodeData>().shellcode), nullptr))
		{
			(void)VirtualProtectEx(process_handle, wfbi.StartRoutine, sizeof(std::declval<ShellcodeData>().shellcode), oPageProtection, &oPageProtection);
			return false;
		}

		(void)VirtualProtectEx(process_handle, wfbi.StartRoutine, sizeof(std::declval<ShellcodeData>().shellcode), oPageProtection, &oPageProtection);

		new_thread_minimum = wfbi.TotalWorkerCount;
		(void)pfNtSetInformationWorkerFactory(worker_factory_handle, WorkerFactoryThreadMinimum, &new_thread_minimum, sizeof(ULONG));

		return true;
	}

	bool TpWorkInsertion(HANDLE const worker_factory_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");
		NtQueryInformationWorkerFactory pfNtQueryInformationWorkerFactory = reinterpret_cast<NtQueryInformationWorkerFactory>(GetProcAddress(ntdll_module, "NtQueryInformationWorkerFactory"));

		WORKER_FACTORY_BASIC_INFORMATION wfbi{};
		(void)pfNtQueryInformationWorkerFactory(worker_factory_handle, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi), nullptr);

		ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle,
			(DWORD64)Dummy - (DWORD64)ShellcodeForwarder,
			ShellcodeForwarder
		};

		if (shellcode.internal_error)
			return false;

		void* allocated_tp_work = VirtualAllocEx(process_handle, nullptr, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_tp_work)
			return false;

		FULL_TP_POOL copied_pool = {};
		if (!ReadProcessMemory(process_handle, wfbi.StartParameter, &copied_pool, sizeof(FULL_TP_POOL), nullptr))
			return false;

		if(!WriteProcessMemory(process_handle, shellcode.allocated_args, &shellcode.pool_data, sizeof(POOL_DATA), nullptr))
		{
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing pool data", allocated_tp_work);
			return false;
		}

		PFULL_TP_WORK p_full_tp_work = reinterpret_cast<PFULL_TP_WORK>(CreateThreadpoolWork(reinterpret_cast<PTP_WORK_CALLBACK>(shellcode.allocated_shellcode), nullptr, nullptr));
		
		if (!p_full_tp_work)
			return false;

		LIST_ENTRY queue_head = {};
		if(!ReadProcessMemory(process_handle, &copied_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue, &queue_head, sizeof(LIST_ENTRY), nullptr))
		{
			CONSOLE_LOG_ERROR("Error reading queue head")
			queue_head.Blink = &copied_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;
		}

		p_full_tp_work->CleanupGroupMember.Pool		= reinterpret_cast<PFULL_TP_POOL>(wfbi.StartParameter);
		p_full_tp_work->Task.ListEntry.Flink		= queue_head.Flink;
		p_full_tp_work->Task.ListEntry.Blink		= &copied_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;
		p_full_tp_work->WorkState.Exchange			= 0x3;

		if(!WriteProcessMemory(process_handle, allocated_tp_work, p_full_tp_work, sizeof(*p_full_tp_work), nullptr))
		{
			p_full_tp_work->CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolWork(reinterpret_cast<PTP_WORK>(p_full_tp_work));
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed writing our tp work struct", allocated_tp_work);
			return false;
		}

		void* o_links [2] = {nullptr, nullptr};
		if(!ReadProcessMemory(process_handle, &copied_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue, &o_links[0], sizeof(o_links), nullptr))
		{
			p_full_tp_work->CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolWork(reinterpret_cast<PTP_WORK>(p_full_tp_work));
			CONSOLE_LOG_ERROR("failed reading queue links")
			return false;
		}

		PLIST_ENTRY p_tp_work_list = &static_cast<PFULL_TP_WORK>(allocated_tp_work)->Task.ListEntry;

		if (!WriteProcessMemory(process_handle, &copied_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &p_tp_work_list, sizeof(void*), nullptr))
		{
			p_full_tp_work->CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolWork(reinterpret_cast<PTP_WORK>(p_full_tp_work));
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed writing into List Entry", allocated_tp_work);
			return false;
		}

		if (!WriteProcessMemory(process_handle, &copied_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &p_tp_work_list, sizeof(void*), nullptr))
		{
			p_full_tp_work->CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolWork(reinterpret_cast<PTP_WORK>(p_full_tp_work));
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed writing into List Entry", allocated_tp_work);
			return false;
		}

		//Better ways of doing this however idc.
		//also executing is very different on different processes some games/apps are quicker than others executing this shit sometimes it won't work at all
		Sleep(30000);

		DWORD thread_id = 0;
		if (!ReadProcessMemory(process_handle, &reinterpret_cast<POOL_DATA*>(shellcode.allocated_args)->thread_id, &thread_id, sizeof(DWORD), nullptr))
			CONSOLE_LOG_ERROR("Cant get thread id, execution failed!")

		//had some issues this is old code but also works for a check if executed lol
		if(thread_id)
		{
			p_full_tp_work->CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolWork(reinterpret_cast<PTP_WORK>(p_full_tp_work));
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_work);
			return true;

			//caused some issues therefore I will leave the thread suspended

			//HANDLE thread_handle = OpenThread(THREAD_TERMINATE, false, thread_id);
			//TerminateThread(thread_handle, 0);
			//CloseHandle(thread_handle);
		}

		if (!WriteProcessMemory(process_handle, &copied_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue, &o_links, sizeof(o_links), nullptr))
		{
			p_full_tp_work->CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolWork(reinterpret_cast<PTP_WORK>(p_full_tp_work));
			Utility::FreeAllocatedMemoryEx(process_handle, "Failed writing into List Entry", allocated_tp_work);
			return false;
		}

		p_full_tp_work->CleanupGroupMember.Refcount.Refcount = 0;
		CloseThreadpoolWork(reinterpret_cast<PTP_WORK>(p_full_tp_work));
		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_work);

		return false;
	}

	bool TpJobInsertion(HANDLE const io_completion_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		TpAllocJobNotification pfTpAllocJobNotification = reinterpret_cast<TpAllocJobNotification>(GetProcAddress(ntdll, "TpAllocJobNotification"));
		TpReleaseJobNotification pfTpReleaseJobNotification = reinterpret_cast<TpReleaseJobNotification>(GetProcAddress(ntdll, "TpReleaseJobNotification"));

		HANDLE job_object_handle = CreateJobObjectW(nullptr, nullptr);
		
		if(!job_object_handle)
		{
			CONSOLE_LOG_ERROR("failed creating a job")
			return false;
		}

		ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle
		};

		if (shellcode.internal_error)
		{
			CloseHandle(job_object_handle);
			return false;
		}

		PFULL_TP_JOB full_tp_job = nullptr;
		(void)pfTpAllocJobNotification(&full_tp_job, job_object_handle, shellcode.allocated_shellcode, nullptr, nullptr);

		if(!full_tp_job)
		{
			CloseHandle(job_object_handle);
			CONSOLE_LOG_ERROR("TpAllocJobNotification failed allocating PFULL_TP_JOB")
			return false;
		}

		void* allocated_tp_job = VirtualAllocEx(process_handle, nullptr, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_tp_job)
		{
			pfTpReleaseJobNotification(full_tp_job);
			CloseHandle(job_object_handle);
			CONSOLE_LOG_ERROR("failed allocating tp job")
			return false;
		}

		if(!WriteProcessMemory(process_handle, allocated_tp_job, full_tp_job, sizeof(*full_tp_job), nullptr))
		{
			pfTpReleaseJobNotification(full_tp_job);
			CloseHandle(job_object_handle);
			Utility::FreeAllocatedMemoryEx(process_handle, "failed writing full_tp_job", allocated_tp_job);
			return false;
		}

		JOBOBJECT_ASSOCIATE_COMPLETION_PORT completionPort = {};

		if(!SetInformationJobObject(job_object_handle, JobObjectAssociateCompletionPortInformation, &completionPort, sizeof(completionPort)))
		{
			pfTpReleaseJobNotification(full_tp_job);
			CloseHandle(job_object_handle);
			Utility::FreeAllocatedMemoryEx(process_handle, "SetInformationJobObject failed", allocated_tp_job);
			return false;
		}

		completionPort.CompletionKey = allocated_tp_job;
		completionPort.CompletionPort = io_completion_handle;

		if (!SetInformationJobObject(job_object_handle, JobObjectAssociateCompletionPortInformation, &completionPort, sizeof(completionPort)))
		{
			pfTpReleaseJobNotification(full_tp_job);
			CloseHandle(job_object_handle);
			Utility::FreeAllocatedMemoryEx(process_handle, "SetInformationJobObject failed", allocated_tp_job);
			return false;
		}

		//you can also use the targets handle however requires additional handle permissions -> PROCESS_SET_QUOTA | PROCESS_TERMINATE;
		if (!AssignProcessToJobObject(job_object_handle, GetCurrentProcess()))
		{
			pfTpReleaseJobNotification(full_tp_job);
			CloseHandle(job_object_handle);
			Utility::FreeAllocatedMemoryEx(process_handle, "AssignProcessToJobObject failed", allocated_tp_job);
			return false;
		}

		Sleep(2000);

		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_job);
		pfTpReleaseJobNotification(full_tp_job); 
		CloseHandle(job_object_handle);

		return true;
	}

	bool TpDirect(HANDLE const io_completion_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle
		};

		if (shellcode.internal_error)
			return false;

		TP_DIRECT tp_direct {.Callback = shellcode.allocated_shellcode };

		void* allocated_tp_direct = VirtualAllocEx(process_handle, nullptr, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if(!allocated_tp_direct)
		{
			CONSOLE_LOG_ERROR("failed allocating tp_direct")
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_tp_direct, &tp_direct, sizeof(TP_DIRECT), nullptr))
		{
			CONSOLE_LOG_ERROR("WriteProcessMemory failed")
			return false;
		}

		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

		NtSetIoCompletion pfNtSetIoCompletion = reinterpret_cast<NtSetIoCompletion>(GetProcAddress(ntdll, "NtSetIoCompletion"));
		(void)pfNtSetIoCompletion(io_completion_handle, allocated_tp_direct, 0, 0, 0);

		Sleep(3000);

		return true;
	}

	bool TpWait(HANDLE const io_completion_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle,
			(DWORD64)Dummy - (DWORD64)ShellcodeForwarder,
			ShellcodeForwarder
		};

		if (shellcode.internal_error)
			return false;

		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		NtAssociateWaitCompletionPacket pfNtAssociateWaitCompletionPacket = reinterpret_cast<NtAssociateWaitCompletionPacket>(GetProcAddress(ntdll, "NtAssociateWaitCompletionPacket"));

		PFULL_TP_WAIT p_tp_wait = reinterpret_cast<PFULL_TP_WAIT>(CreateThreadpoolWait(static_cast<PTP_WAIT_CALLBACK>(shellcode.allocated_shellcode), nullptr, nullptr));
		
		//TppCleanupGroupMemberDestroy crash bcs of PoolObjectLinks
		//lea rax, [rbx+98h] should be p_tp_wait->Timer.Work.CleanupGroupMember.PoolObjectLinks then it does mov rcx, [rax+8] which should be [p_tp_wait->Timer.Work.CleanupGroupMember.PoolObjectLinks.Blink]
		//p_tp_wait->Timer.Work.CleanupGroupMember.PoolObjectLinks.Flink = &p_tp_wait->Timer.Work.CleanupGroupMember.PoolObjectLinks;
		//p_tp_wait->Timer.Work.CleanupGroupMember.PoolObjectLinks.Blink = &p_tp_wait->Timer.Work.CleanupGroupMember.PoolObjectLinks;
		//p_tp_wait->Timer.Work.CleanupGroupMember.Pool->Refcount.Refcount = 0;
		//TpAdjustBindingCount crash at lock xadd [rcx+1B0h], eax -> bcs rcx was from caller [rcx + 0x90] which is [tp_wait->Timer.Work.CleanupGroupMember.Pool] so we need to give it trash memory to write on
		//RtlFailFast is fucking me rn bcs im dumb

		//TpAdjustBindingCount crash fix with this line of code
		//p_tp_wait->Timer.Work.CleanupGroupMember.Pool = (FULL_TP_POOL*)VirtualAllocEx(process_handle, nullptr, sizeof(FULL_TP_POOL), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		//most depressing shit ever I couldn't get this to work without my cheap solution by suspending the thread, listen at this point im super bored working on this project I want to get back doing something else
		//that's why I will probably leave this as it is. All of this is basically a copy of the POC from the guy who found out about all of this. At this point I'm just making it work with my injector without crashes.
		//It's fucking time-consuming to make all of this properly work at least for me. The project idea was for me to learn about new stuff, but I still have to learn about other stuff as well
		//TODO check on this when I have more free time 

		if(!p_tp_wait)
		{
			CONSOLE_LOG_ERROR("CreateThreadpoolWait failed")
			return false;
		}

		//omg my eyes wtf
		//TODO maybe find a better/cleaner way allocating this shit 
		void* allocated_tp_wait = VirtualAllocEx(process_handle, nullptr, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_tp_wait)
		{
			CloseThreadpoolWait(reinterpret_cast<PTP_WAIT>(p_tp_wait));
			CONSOLE_LOG_ERROR("Allocation failed")
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_tp_wait, p_tp_wait, sizeof(FULL_TP_WAIT), nullptr))
		{
			CloseThreadpoolWait(reinterpret_cast<PTP_WAIT>(p_tp_wait));
			Utility::FreeAllocatedMemoryEx(process_handle, "WriteProcessMemory failed", allocated_tp_wait);
			return false;
		}

		void* allocated_tp_direct = VirtualAllocEx(process_handle, nullptr, sizeof(TP_DIRECT) * 1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!allocated_tp_direct)
		{
			CloseThreadpoolWait(reinterpret_cast<PTP_WAIT>(p_tp_wait));
			Utility::FreeAllocatedMemoryEx(process_handle, "Allocation failed", allocated_tp_wait);
			return false;
		}

		if (!WriteProcessMemory(process_handle, allocated_tp_direct, &p_tp_wait->Direct, sizeof(TP_DIRECT), nullptr))
		{
			CloseThreadpoolWait(reinterpret_cast<PTP_WAIT>(p_tp_wait));
			Utility::FreeAllocatedMemoryEx(process_handle, "WriteProcessMemory failed", allocated_tp_wait, allocated_tp_direct);
			return false;
		}

		HANDLE event_handle = CreateEventW(nullptr, false, false, nullptr);

		if(!event_handle)
		{
			CloseThreadpoolWait(reinterpret_cast<PTP_WAIT>(p_tp_wait));
			Utility::FreeAllocatedMemoryEx(process_handle, "CreateEventW failed", allocated_tp_wait, allocated_tp_direct);
			return false;
		}

		(void)pfNtAssociateWaitCompletionPacket(
			p_tp_wait->WaitPkt, io_completion_handle, 
			event_handle, allocated_tp_direct, 
			allocated_tp_wait, NULL, 
			NULL, nullptr);

		(void)SetEvent(event_handle);
		Sleep(2000);

		DWORD thread_id = 0;
		if (!ReadProcessMemory(process_handle, &reinterpret_cast<POOL_DATA*>(shellcode.allocated_args)->thread_id, &thread_id, sizeof(DWORD), nullptr))
			CONSOLE_LOG_ERROR("Cant get thread id, execution failed!")

		if (thread_id)
		{
			CloseThreadpoolWait(reinterpret_cast<PTP_WAIT>(p_tp_wait));
			CloseHandle(event_handle);
			Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_wait, allocated_tp_direct);
			return true;
		}

		CloseThreadpoolWait(reinterpret_cast<PTP_WAIT>(p_tp_wait));
		CloseHandle(event_handle);
		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_wait, allocated_tp_direct);

		return false;
	}

	bool TpTimer(HANDLE const worker_factory_handle, HANDLE const ir_timer_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		NtQueryInformationWorkerFactory pfNtQueryInformationWorkerFactory = reinterpret_cast<NtQueryInformationWorkerFactory>(GetProcAddress(ntdll, "NtQueryInformationWorkerFactory"));
		NtSetTimer2 pfNtSetTimer2 = reinterpret_cast<NtSetTimer2>(GetProcAddress(ntdll, "NtSetTimer2"));
		NtCancelTimer2 pfNtCancelTimer2 = reinterpret_cast<NtCancelTimer2>(GetProcAddress(ntdll, "NtCancelTimer2"));

		WORKER_FACTORY_BASIC_INFORMATION wfbi{};
		(void)pfNtQueryInformationWorkerFactory(worker_factory_handle, WorkerFactoryBasicInformation, &wfbi, sizeof(wfbi), nullptr);

		ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle,
			(DWORD64)Dummy - (DWORD64)ShellcodeForwarder,
			ShellcodeForwarder
		};

		if (shellcode.internal_error)
			return false;

		PFULL_TP_TIMER p_full_tp_timer = reinterpret_cast<PFULL_TP_TIMER>(CreateThreadpoolTimer(reinterpret_cast<PTP_TIMER_CALLBACK>(shellcode.allocated_shellcode), nullptr, nullptr));

		if(!p_full_tp_timer)
		{
			CONSOLE_LOG_ERROR("CreateThreadpoolTimer failed")
			return false;
		}

		void* allocated_tp_timer = VirtualAllocEx(process_handle, nullptr, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if(!allocated_tp_timer)
		{
			p_full_tp_timer->Work.CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolTimer(reinterpret_cast<PTP_TIMER>(p_full_tp_timer));
			CONSOLE_LOG_ERROR("allocating tp_timer failed")
			return false;
		}

		p_full_tp_timer->Work.CleanupGroupMember.Pool		= static_cast<PFULL_TP_POOL>(wfbi.StartParameter);

		p_full_tp_timer->DueTime							= -10000000;
		p_full_tp_timer->WindowEndLinks.Key					= -10000000;
		p_full_tp_timer->WindowStartLinks.Key				= -10000000;

		p_full_tp_timer->WindowStartLinks.Children.Flink	= &reinterpret_cast<PFULL_TP_TIMER>(allocated_tp_timer)->WindowStartLinks.Children;
		p_full_tp_timer->WindowStartLinks.Children.Blink	= &reinterpret_cast<PFULL_TP_TIMER>(allocated_tp_timer)->WindowStartLinks.Children;

		p_full_tp_timer->WindowEndLinks.Children.Flink		= &reinterpret_cast<PFULL_TP_TIMER>(allocated_tp_timer)->WindowEndLinks.Children;
		p_full_tp_timer->WindowEndLinks.Children.Blink		= &reinterpret_cast<PFULL_TP_TIMER>(allocated_tp_timer)->WindowEndLinks.Children;

		if(!WriteProcessMemory(process_handle, allocated_tp_timer, p_full_tp_timer, sizeof(FULL_TP_TIMER), nullptr))
		{
			p_full_tp_timer->Work.CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolTimer(reinterpret_cast<PTP_TIMER>(p_full_tp_timer));
			Utility::FreeAllocatedMemoryEx(process_handle, "writing tp_timer failed", allocated_tp_timer);
			return false;
		}

		void* owindow_start_arr[2] = {};

		if (!ReadProcessMemory(process_handle, &static_cast<PFULL_TP_POOL>(wfbi.StartParameter)->TimerQueue.AbsoluteQueue.WindowStart, owindow_start_arr, sizeof(owindow_start_arr), nullptr))
		{
			p_full_tp_timer->Work.CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolTimer(reinterpret_cast<PTP_TIMER>(p_full_tp_timer));
			Utility::FreeAllocatedMemoryEx(process_handle, "Reading WindowStart failed", allocated_tp_timer);
			return false;
		}

		void* window_start_arr[2] = { &reinterpret_cast<PFULL_TP_TIMER>(allocated_tp_timer)->WindowStartLinks, &reinterpret_cast<PFULL_TP_TIMER>(allocated_tp_timer)->WindowEndLinks };

		if (!WriteProcessMemory(process_handle, &static_cast<PFULL_TP_POOL>(wfbi.StartParameter)->TimerQueue.AbsoluteQueue.WindowStart, window_start_arr, sizeof(window_start_arr), nullptr))
		{
			p_full_tp_timer->Work.CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolTimer(reinterpret_cast<PTP_TIMER>(p_full_tp_timer));
			Utility::FreeAllocatedMemoryEx(process_handle, "writing to WindowStart failed", allocated_tp_timer);
			return false;
		}

		T2_SET_PARAMETERS t2_parameters = {};
		LARGE_INTEGER due_time = { .QuadPart = 0 };

		(void)pfNtSetTimer2(ir_timer_handle, &due_time, nullptr, &t2_parameters);
		Sleep(4000);

		if (!WriteProcessMemory(process_handle, &static_cast<PFULL_TP_POOL>(wfbi.StartParameter)->TimerQueue.AbsoluteQueue.WindowStart, owindow_start_arr, sizeof(owindow_start_arr), nullptr))
		{
			pfNtCancelTimer2(ir_timer_handle, &t2_parameters);
			p_full_tp_timer->Work.CleanupGroupMember.Refcount.Refcount = 0;
			CloseThreadpoolTimer(reinterpret_cast<PTP_TIMER>(p_full_tp_timer));
			Utility::FreeAllocatedMemoryEx(process_handle, "writing to WindowStart failed", allocated_tp_timer);
			return false;
		}

		DWORD thread_id = 0;
		if (!ReadProcessMemory(process_handle, &reinterpret_cast<POOL_DATA*>(shellcode.allocated_args)->thread_id, &thread_id, sizeof(DWORD), nullptr))
			CONSOLE_LOG_ERROR("Cant get thread id, execution failed!")

			if (thread_id)
			{
				pfNtCancelTimer2(ir_timer_handle, &t2_parameters);
				p_full_tp_timer->Work.CleanupGroupMember.Refcount.Refcount = 0;
				CloseThreadpoolTimer(reinterpret_cast<PTP_TIMER>(p_full_tp_timer));
				Utility::FreeAllocatedMemoryEx(process_handle, "writing to WindowStart failed", allocated_tp_timer);
				return true;
			}

		pfNtCancelTimer2(ir_timer_handle, &t2_parameters);
		p_full_tp_timer->Work.CleanupGroupMember.Refcount.Refcount = 0;
		CloseThreadpoolTimer(reinterpret_cast<PTP_TIMER>(p_full_tp_timer));
		Utility::FreeAllocatedMemoryEx(process_handle, "writing to WindowStart failed", allocated_tp_timer);

		return false;
	}

	bool TpIo(HANDLE const io_completion_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle,
			(DWORD64)Dummy - (DWORD64)ShellcodeForwarder,
			ShellcodeForwarder
		};

		if (shellcode.internal_error)
			return false;

		HMODULE ntdll										= GetModuleHandleW(L"ntdll.dll");
		NtSetInformationFile pfNtSetInformationFile			= reinterpret_cast<NtSetInformationFile>(GetProcAddress(ntdll, "NtSetInformationFile"));
		NtQueryInformationFile pfNtQueryInformationFile		= reinterpret_cast<NtQueryInformationFile>(GetProcAddress(ntdll, "NtQueryInformationFile"));

		wchar_t temp_path_buffer[MAX_PATH] {};
		if (!GetTempPathW(MAX_PATH, temp_path_buffer))
		{
			CONSOLE_LOG_ERROR("failed getting file path to temp folder")			
			return false;
		}

		wchar_t* temp_folder_path = temp_path_buffer;
		wchar_t* file_name = _wtempnam(temp_folder_path, L"MadInjector");

		//wchar_t temp_file_path[MAX_PATH]{};
		//if(!GetTempFileNameW(temp_folder_path, L"MAD", NULL, temp_file_path))
		//{
		//	CONSOLE_LOG_ERROR("failed creating file in temp folder")
		//	return false;
		//}

		//if (GetFileAttributesW(temp_file_path) == INVALID_FILE_ATTRIBUTES)
		//	CONSOLE_LOG("GetTempFileNameW only create a file name")
		
		HANDLE file_handle = CreateFileW(
			file_name, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE,
			nullptr);
		
		if(!file_handle)
		{
			//_wtempnam uses malloc using delete here is UB
			free(file_name);
			CONSOLE_LOG_ERROR("CreateFileW failed")
			return false;
		}

		PFULL_TP_IO p_full_tp_io = reinterpret_cast<PFULL_TP_IO>(CreateThreadpoolIo(file_handle, reinterpret_cast<PTP_WIN32_IO_CALLBACK>(shellcode.allocated_shellcode), nullptr, nullptr));

		if(!p_full_tp_io)
		{
			CloseHandle(file_handle);
			free(file_name);
			CONSOLE_LOG_ERROR("CreateThreadpoolIo failed")
			return false;
		}

		p_full_tp_io->CleanupGroupMember.Callback = shellcode.allocated_shellcode;
		{
			//Only > c++20
			//PendingIrpCount is volatile therefore this applies -> If the type of expression is volatile-qualified, the decrement/increment is deprecated.
			//https://en.cppreference.com/w/cpp/language/operator_incdec
			INT32 increment = p_full_tp_io->PendingIrpCount + 1;
			p_full_tp_io->PendingIrpCount = increment;
		}

		void* allocated_tp_io = VirtualAllocEx(process_handle, nullptr, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if(!allocated_tp_io)
		{
			CloseHandle(file_handle);
			free(file_name);
			CONSOLE_LOG_ERROR("allocating memory for FULL_TP_IO failed")
			return false;
		}

		if(!WriteProcessMemory(process_handle, allocated_tp_io, p_full_tp_io, sizeof(*p_full_tp_io), nullptr))
		{
			CloseHandle(file_handle);
			free(file_name);
			Utility::FreeAllocatedMemoryEx(process_handle, "Writing FULL_TP_IO failed", allocated_tp_io);
			return false;
		}

		FILE_COMPLETION_INFORMATION o_fci {};

		IO_STATUS_BLOCK iosb{};
		(void)pfNtQueryInformationFile(file_handle, &iosb, &o_fci, sizeof(o_fci), FileCompletionInformation);

		FILE_COMPLETION_INFORMATION fci =
		{
			.Port = io_completion_handle,
			.Key = &reinterpret_cast<PFULL_TP_IO>(allocated_tp_io)->Direct
		};

		iosb = IO_STATUS_BLOCK{};
		(void)pfNtSetInformationFile(file_handle, &iosb, &fci, sizeof(fci), FileReplaceCompletionInformation);

		OVERLAPPED overlap {};
		WriteFile(file_handle, file_name, 1, nullptr, &overlap);

		Sleep(2000);

		//will always be 0 for both members idk if this is necessary 
		iosb = IO_STATUS_BLOCK{};
		(void)pfNtSetInformationFile(file_handle, &iosb, &o_fci, sizeof(o_fci), FileReplaceCompletionInformation);

		//I was about to call NtSetInformationFile with FileDispositionInformation with DeleteFile set to true holy fuck what is wrong with me
		//I forgot FILE_FLAG_DELETE_ON_CLOSE exists xD 

		CloseHandle(file_handle);
		Utility::FreeAllocatedMemoryEx(process_handle, "", allocated_tp_io);
		free(file_name);
		return true;
	}

	bool TpAlpc(HANDLE const io_completion_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle)
	{
		ShellcodeData shellcode
		{
			allocated_memory_code,
			allocated_memory_thread_data,
			process_handle,
		};

		if (shellcode.internal_error)
			return false;

		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

		NtAlpcCreatePort pfNtAlpcCreatePort				= reinterpret_cast<NtAlpcCreatePort>(GetProcAddress(ntdll, "NtAlpcCreatePort"));
		TpAllocAlpcCompletion pfTpAllocAlpcCompletion	= reinterpret_cast<TpAllocAlpcCompletion>(GetProcAddress(ntdll, "TpAllocAlpcCompletion"));
		NtAlpcSetInformation pfNtAlpcSetInformation		= reinterpret_cast<NtAlpcSetInformation>(GetProcAddress(ntdll, "NtAlpcSetInformation"));
		NtAlpcConnectPort pfNtAlpcConnectPort			= reinterpret_cast<NtAlpcConnectPort>(GetProcAddress(ntdll, "NtAlpcConnectPort"));
		RtlInitUnicodeString pfRtlInitUnicodeString		= reinterpret_cast<RtlInitUnicodeString>(GetProcAddress(ntdll, "RtlInitUnicodeString"));
		NtAlpcDisconnectPort pfNtAlpcDisconnectPort     = reinterpret_cast<NtAlpcDisconnectPort>(GetProcAddress(ntdll, "NtAlpcDisconnectPort"));

		HANDLE port_handle_fake = nullptr;
		(void)pfNtAlpcCreatePort(&port_handle_fake, nullptr, nullptr);

		PFULL_TP_ALPC p_full_tp_alpc = nullptr;
		(void)pfTpAllocAlpcCompletion(&p_full_tp_alpc, port_handle_fake, reinterpret_cast<PTP_ALPC_CALLBACK>(shellcode.allocated_shellcode), nullptr, nullptr);

		UNICODE_STRING object_us{};
		pfRtlInitUnicodeString(&object_us, L"\\RPC Control\\MHALPC_TPIN_KO");

		OBJECT_ATTRIBUTES object_attributes
		{
			.Length = sizeof(OBJECT_ATTRIBUTES),
			.ObjectName = &object_us
		};

		ALPC_PORT_ATTRIBUTES alpc_port_attributes
		{
			.Flags = 0x20000,
			.MaxMessageLength = 328
		};

		HANDLE port_handle_real = nullptr;
		(void)pfNtAlpcCreatePort(&port_handle_real, &object_attributes, &alpc_port_attributes);

		void* allocated_tp_alpc = VirtualAllocEx(process_handle, nullptr, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if(!allocated_tp_alpc)
		{
			CONSOLE_LOG_ERROR("allocating FULL_TP_ALPC failed")
			CloseHandle(port_handle_real);
			return false;
		}

		if(!WriteProcessMemory(process_handle, allocated_tp_alpc, p_full_tp_alpc, sizeof(FULL_TP_ALPC), nullptr))
		{
			CONSOLE_LOG_ERROR("writing FULL_TP_ALPC failed")
			CloseHandle(port_handle_fake);
			CloseHandle(port_handle_real);
			return false;
		}

		ALPC_PORT_ASSOCIATE_COMPLETION_PORT alpc_port_associate_completion_port
		{
			.CompletionKey = allocated_tp_alpc,
			.CompletionPort = io_completion_handle
		};

		(void)pfNtAlpcSetInformation(port_handle_real, AlpcAssociateCompletionPortInformation, &alpc_port_associate_completion_port, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));

		OBJECT_ATTRIBUTES alpc_attributes { .Length = sizeof(OBJECT_ATTRIBUTES) };

		//don't ask me why I did this that way probably boredom. This is the same as in the POC that I got this code from
		//I just set the lower and higher bytes myself instead of using the union -> 2 + sizeof(PORT_MESSAGE) = TotalLength and 2 = DataLength which are the lower 2 bytes
		ALPC_MESSAGE alpc_message
		{//.PortHeader
			{//.u1
				{.Length = (static_cast<ULONG>(2 + sizeof(PORT_MESSAGE)) << 16) | 2 }
			}
		};

		alpc_message.PortMessage[0] = 'W';
		alpc_message.PortMessage[1] = '\0';

		SIZE_T alpc_message_size = sizeof(ALPC_MESSAGE);
		HANDLE connect_handle = nullptr;

		LARGE_INTEGER timeout { .QuadPart = -10000000 };

		(void)pfNtAlpcConnectPort(&connect_handle,
			&object_us,
			&alpc_attributes,
			&alpc_port_attributes,
			0x20000,
			nullptr,
			reinterpret_cast<PPORT_MESSAGE>(&alpc_message),
			&alpc_message_size,
			nullptr,
			nullptr,
			&timeout
		);

		Sleep(1500);

		(void)pfNtAlpcDisconnectPort(connect_handle, false);

		CloseHandle(port_handle_fake);
		CloseHandle(port_handle_real);
		CloseHandle(connect_handle);

		return true;
	}

	bool Execute(HANDLE const process_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, DWORD64 additional_flags, DWORD pid)
	{
		if(additional_flags & MI_WORKER_THREAD_CREATION)
		{
			if(HANDLE wfh = GetHandleOfType(L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS, process_handle, pid); wfh)
			{
				const bool result = WorkerFactoryThreadCreation(wfh, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(wfh);
				return result;
			}
		}

		if (additional_flags & MI_POOL_TP_WORK_INSERTION)
		{
			if (HANDLE wfh = GetHandleOfType(L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS, process_handle, pid); wfh)
			{
				const bool result = TpWorkInsertion(wfh, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(wfh);
				return result;
			}
		}

		if (additional_flags & MI_POOL_TP_JOB_INSERTION)
		{
			if (HANDLE ioch = GetHandleOfType(L"IoCompletion", IO_COMPLETION_ALL_ACCESS, process_handle, pid); ioch)
			{
				if (additional_flags & INSIDE_HIJACKED_HANDLE_PROCESS)
				{
					const bool result = SessionRestrictionFix::TpJobInsertion(ioch, allocated_memory_code, allocated_memory_thread_data, process_handle);
					CloseHandle(ioch);
					return result;
				}

				const bool result = TpJobInsertion(ioch, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(ioch);
				return result;
			}
		}

		if (additional_flags & MI_POOL_TP_DIRECT)
		{
			if (HANDLE ioch = GetHandleOfType(L"IoCompletion", IO_COMPLETION_ALL_ACCESS, process_handle, pid); ioch)
			{
				const bool result = TpDirect(ioch, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(ioch);
				return result;
			}
		}

		if (additional_flags & MI_POOL_TP_WAIT)
		{
			if (HANDLE ioch = GetHandleOfType(L"IoCompletion", IO_COMPLETION_ALL_ACCESS, process_handle, pid); ioch)
			{
				const bool result = TpWait(ioch, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(ioch);
				return result;
			}
		}

		if (additional_flags & MI_POOL_TP_TIMER)
		{
			if (HANDLE irth = GetHandleOfType(L"IRTimer", TIMER_ALL_ACCESS, process_handle, pid), 
				wfh = GetHandleOfType(L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS, process_handle, pid); 
				irth && wfh)
			{
				const bool result = TpTimer(wfh, irth, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(irth);
				CloseHandle(wfh);
				return result;
			}
		}

		if (additional_flags & MI_POOL_TP_IO)
		{
			if (HANDLE ioch = GetHandleOfType(L"IoCompletion", IO_COMPLETION_ALL_ACCESS, process_handle, pid); ioch)
			{
				const bool result = TpIo(ioch, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(ioch);
				return result;
			}
		}

		if (additional_flags & MI_POOL_TP_ALPC)
		{
			if (HANDLE ioch = GetHandleOfType(L"IoCompletion", IO_COMPLETION_ALL_ACCESS, process_handle, pid); ioch)
			{
				const bool result = TpAlpc(ioch, allocated_memory_code, allocated_memory_thread_data, process_handle);
				CloseHandle(ioch);
				return result;
			}
		}

		return false;
	}
}

#endif