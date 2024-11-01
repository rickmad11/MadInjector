#pragma once

inline BOOL WINAPI ConsoleHandlerCallback(DWORD CtrlType)
{
	if (CtrlType == CTRL_CLOSE_EVENT || CtrlType == CTRL_SHUTDOWN_EVENT)
	{
		Console::get()->UnInitConsole();
		return TRUE;
	}

	return FALSE;
}

inline void SetConsoleCallback()
{
	(void)SetConsoleCtrlHandler(ConsoleHandlerCallback, true);
}

inline void RemoveConsoleCallback()
{
	(void)SetConsoleCtrlHandler(ConsoleHandlerCallback, false);
}