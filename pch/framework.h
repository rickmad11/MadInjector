#pragma once

//#define WIN32_LEAN_AND_MEAN             
// Windows Header Files
#include <windows.h>
#include <Shellapi.h>
#include <TlHelp32.h>
#include <AclAPI.h>
#include <versionhelpers.h>

//STL
#include <string>
#include <map>
#include <unordered_map>
#include <set>
#include <typeindex>
#include <array>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <thread>

//Symbols
#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

//Internet
#include <wininet.h>
#pragma comment(lib,"Wininet.lib")

//lib that we apparently need
#pragma comment(lib,"Urlmon.lib")

//Custom
#include "SymbolLoader/SymbolLoader.h"
#include "SymbolParser/SymbolParser.h"
#include "Utility/FunctionInterface.hpp"
#include "Console/Console.h"
#include "WinTypes/WinTypes.hpp"
#include "Utility/HelperFunctions.hpp"
#include "WinTypes/ManualMapTypes.hpp"
#include "WinTypes/VEHTypes.hpp"

//MSDN EncodeRemotePointer is in KernelBase.dll not in Kernel32.dll they did not update their page
//dumpbin can be used to find the lib file for a specific function this one works just fine
//now im having issues with loading my dll bro I will just resolve the address myself 
//#pragma comment(lib,"onecore.lib")