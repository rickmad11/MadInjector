#pragma once

namespace SessionRestrictionFix
{
	bool TpJobInsertion(HANDLE const io_completion_handle, void* const allocated_memory_code, void* const allocated_memory_thread_data, HANDLE const process_handle);
}