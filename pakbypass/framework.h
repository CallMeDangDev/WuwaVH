#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define NOMINMAX

// Windows Header Files
#include <windows.h>
#include <psapi.h>

// C++ Standard Library
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <functional>
#include <unordered_map>
#include <cstdint>
#include <iomanip>

#pragma comment(lib, "psapi.lib")
