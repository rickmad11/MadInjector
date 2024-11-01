#pragma once

struct FunctionInterface final
{
	FunctionInterface() = default;

	FunctionInterface(FunctionInterface const&) = delete;
	FunctionInterface& operator=(FunctionInterface const&) = delete;

	FunctionInterface(FunctionInterface&&) = delete;
	FunctionInterface& operator=(FunctionInterface&&) = delete;

	~FunctionInterface() = default;

	template<typename T>
	void Insert(std::wstring const& function_name, T pFunction)
	{
		std::type_index type = typeid(pFunction);
		function_map.insert(std::make_pair(function_name, std::make_pair(reinterpret_cast<void(*)(void)>(pFunction), type)));
	}

	template <typename Return, typename... Args>
	Return Invoke(std::wstring const& function_name, Args... args)
	{
		const auto it = function_map.find(function_name);
		if (it == function_map.end())
			return Return{};

		auto oFunction = reinterpret_cast<Return(*)(Args...)>(it->second.first);
		if (it->second.second != typeid(oFunction))
			return Return{};

		return oFunction(std::forward<Args>(args)...);
	}

private:
	std::map<std::wstring, std::pair<void(*)(void), std::type_index>> function_map;
};