template <typename T>
void
Console::Log(T message) const
{
	if constexpr (std::is_same_v<T, const char*>)
	{
		Change_Color(Color::green);
		std::cout << "[+] ";
		Reset_Color();
		std::cout << message << '\n';
	}
	else
	{
		Change_Color(Color::green);
		std::wcout << "[+] ";
		Reset_Color();
		std::wcout << message << '\n';
	}
}

template <typename T>
void
Console::Log(T message, LPVOID addr) const
{
	if constexpr (std::is_same_v<T, const char*>)
	{
		Change_Color(Color::green);
		std::cout << "[+] ";
		Reset_Color();
		std::cout << message << " -> ";
		Change_Color(Color::purple);
		std::cout << addr << '\n';
		Reset_Color();
	}
	else
	{
		Change_Color(Color::green);
		std::cout << "[+] ";
		Reset_Color();
		std::wcout << message << " -> ";
		Change_Color(Color::purple);
		std::wcout << addr << '\n';
		Reset_Color();
	}
}

template <typename T>
void
Console::Log(T message, DWORD64 value) const
{
	if constexpr (std::is_same_v<T, const char*>)
	{
		Change_Color(Color::green);
		std::cout << "[+] ";
		Reset_Color();
		std::cout << message << " -> ";
		Change_Color(Color::light_blue);
		std::cout << value << '\n';
		Reset_Color();
	}
	else
	{
		Change_Color(Color::green);
		std::cout << "[+] ";
		Reset_Color();
		std::wcout << message << " -> ";
		Change_Color(Color::light_blue);
		std::wcout << value << '\n';
		Reset_Color();
	}
}

template <typename T>
void
Console::Log_Error(T message) const
{
	if constexpr (std::is_same_v<T, const char*>)
	{
		Change_Color(Color::red);
		std::cout << "[-] ";
		Reset_Color();
		std::cout << message << '\n';
	}
	else
	{
		Change_Color(Color::red);
		std::wcout << "[-] ";
		Reset_Color();
		std::wcout << message << '\n';
	}
}

template <typename T>
void
Console::Log_Error(T message, LPVOID addr) const
{
	if constexpr (std::is_same_v<T, const char*>)
	{
		Change_Color(Color::red);
		std::cout << "[-] ";
		Reset_Color();
		std::cout << message << " -> ";
		Change_Color(Color::red);
		std::cout << addr << '\n';
		Reset_Color();
	}
	else
	{
		Change_Color(Color::red);
		std::cout << "[-] ";
		Reset_Color();
		std::wcout << message << " -> ";
		Change_Color(Color::red);
		std::wcout << addr << '\n';
		Reset_Color();
	}
}

template <typename T>
void
Console::Log_Error(T message, DWORD64 value) const
{
	if constexpr (std::is_same_v<T, const char*>)
	{
		Change_Color(Color::red);
		std::cout << "[-] ";
		Reset_Color();
		std::cout << message << " -> ";
		Change_Color(Color::red);
		std::cout << value << '\n';
		Reset_Color();
	}
	else
	{
		Change_Color(Color::red);
		std::cout << "[-] ";
		Reset_Color();
		std::wcout << message << " -> ";
		Change_Color(Color::red);
		std::wcout << value << '\n';
		Reset_Color();
	}
}

template <typename... Args>
void
Console::LogArgs(bool error, Args... args) const
{
	if(error)
	{
		Change_Color(Color::red);
		std::cout << "[-] ";
		Reset_Color();
		( (std::wcout << args << ' ') , ...) << '\n';
		Reset_Color();
		return;
	}

	Change_Color(Color::green);
	std::cout << "[+] ";
	Reset_Color();
	( (std::wcout << args << ' ') , ...) << '\n';
	Reset_Color();
}