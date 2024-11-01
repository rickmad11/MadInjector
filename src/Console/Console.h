#pragma once

class Console
{
public:
	Console(Console const&) = delete;
	Console& operator=(Console const&) = delete;
	Console(Console&&) = delete;
	Console& operator=(Console&&) = delete;

	static Console* get() noexcept;

	template <typename T>
	void Log(T message) const;

	template <typename T>
	void Log(T message, LPVOID addr) const;

	template <typename T>
	void Log(T message, DWORD64 value) const;

	template <typename T>
	void Log_Error(T message) const;

	template <typename T>
	void Log_Error(T message, LPVOID addr) const;

	template <typename T>
	void Log_Error(T message, DWORD64 value) const;

	template <typename... Args>
	void LogArgs(bool error, Args... args) const;

public:
	bool InitConsole() noexcept;
	void UnInitConsole() const;

	static bool& CreateNew();
	static bool& UseExisting();

private:
	Console() = default;
	~Console();

private:
	enum class Color : int32_t {
		red = 12,
		purple = 13,
		yellow = 14,
		blue = 9,
		light_blue = 11,
		green = 10
	};

	void Change_Color(Color _color) const;
	void Reset_Color() const;

private:
	inline static FILE* mstream = nullptr;
	bool console_open = false;

	static inline bool create_new_console = false;
	static inline bool use_existing_console = false;
};

#include "Console.tpp"
