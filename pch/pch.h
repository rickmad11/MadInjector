#pragma once

#ifdef MADINJECTOR_EXPORTS
#define MI_API extern "C" __declspec(dllexport)
#else
#define MI_API extern "C" __declspec(dllimport)
#endif

#define CONSOLE_LOG(...) Console::get() ? Console::get()->Log(__VA_ARGS__) : decltype(std::declval<Console>().Log(__VA_ARGS__))();
#define CONSOLE_LOG_ERROR(...) Console::get() ? Console::get()->Log_Error(__VA_ARGS__) : decltype(std::declval<Console>().Log_Error(__VA_ARGS__))();
#define CONSOLE_LOG_ARGS(...) Console::get() ? Console::get()->LogArgs(__VA_ARGS__) : decltype(std::declval<Console>().LogArgs(__VA_ARGS__))();

#include "framework.h"