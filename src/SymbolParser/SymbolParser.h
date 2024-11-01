#pragma once

//https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/Debug/symbol-loading.md

class SymbolParser final
{
public:
	explicit SymbolParser();
	explicit SymbolParser(std::filesystem::path path);
	~SymbolParser();

	SymbolParser(SymbolParser const&) = delete;
	SymbolParser& operator=(SymbolParser const&) = delete;

	SymbolParser(SymbolParser&&) = delete;
	SymbolParser& operator=(SymbolParser&&) = delete;

public:
	template <typename Func>
	static Func FindFunction(const char* FunctionName, bool relative = false);

	template <typename Class>
	static Class FindClass(const char* ClassName);

private:
	inline static HANDLE own_pseudo_handle = nullptr;
	inline static HANDLE handle_to_own_process = nullptr;
};

template<typename Func>
Func SymbolParser::FindFunction(const char* FunctionName, bool relative)
{
	SYMBOL_INFO pSI {};
	pSI.SizeOfStruct = sizeof(pSI);

	if(!SymFromName(handle_to_own_process, FunctionName, &pSI))
		return nullptr;

	if (relative)
		return Func(pSI.Address - pSI.ModBase);

	return Func(pSI.Address);
}

template<typename Class>
Class SymbolParser::FindClass(const char* ClassName)
{
	SYMBOL_INFO pSI{};
	pSI.SizeOfStruct = sizeof(pSI);

	if (!SymFromName(handle_to_own_process, ClassName, &pSI))
		return nullptr;

	return Class(pSI.Address);
}
