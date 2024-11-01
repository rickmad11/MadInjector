#include "pch.h"
#include "Console.h"

bool Console::InitConsole() noexcept
{
	console_open = true;
	//https://stackoverflow.com/questions/40059902/attachconsole-error-5-access-is-denied
	try
	{
		if(!use_existing_console)
		{
			if (!AllocConsole())
				throw std::exception("Console Allocation failed");

			if (freopen_s(&mstream, "CONOUT$", "w", stdout))
				throw std::exception("Stream failed");
		}
	}
	catch (std::exception const& exp)
	{
		MessageBoxA(nullptr, exp.what(), ("Exception Thrown"), MB_OKCANCEL);
		(void)fclose(mstream);
		(void)FreeConsole();
	}

	SetLayeredWindowAttributes(GetConsoleWindow(), RGB(10, 20, 60), 200, LWA_ALPHA);

	return true;
}

void Console::UnInitConsole() const
{
	if(console_open)
	{
		float seconds = 3.f;
		std::cout << "Closing in " << seconds << "...";

		float last_tick = static_cast<float>(clock()) * 0.001f;
		while ( seconds >= 0.f)
		{
			float curr_tick = static_cast<float>(clock()) * 0.001f;
			if((curr_tick - last_tick) > 1.f)
			{
				last_tick = curr_tick;
				--seconds;
				std::cout << seconds << "...";
			}
		}
	}

	if(mstream)
		console_open ? (void)fclose(mstream) : void();

	console_open ? (void)FreeConsole() : void();
}

bool& Console::CreateNew()
{
	return create_new_console;
}

bool& Console::UseExisting()
{
	return use_existing_console;
}

Console* 
Console::get() noexcept
{
	static Console console;
	return (create_new_console || use_existing_console ) ? &console : nullptr;
}

void
Console::Change_Color(Color _color) const {
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<int32_t>(_color));
}

void
Console::Reset_Color() const {
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

Console::~Console()
{
	if (mstream)
		console_open ? (void)fclose(mstream) : void();

	console_open ? (void)FreeConsole() : void();
}
