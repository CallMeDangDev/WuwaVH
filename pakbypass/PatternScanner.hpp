#pragma once
// PatternScanner.hpp - Memory pattern scanning for finding game functions

#include <windows.h>
#include <vector>
#include <string>
#include <optional>
#include <cstdint>
#include "Logger.hpp"

namespace PatternScanner
{
    struct PatternByte
    {
        uint8_t value;
        bool    wildcard;
    };

    // Parse pattern string like "48 89 5C 24 ?? 48 89 74 24 ?? 57"
    inline std::vector<PatternByte> ParsePattern(const char* pattern)
    {
        std::vector<PatternByte> result;
        const char* p = pattern;

        while (*p)
        {
            while (*p == ' ') p++;
            if (!*p) break;

            if (*p == '?')
            {
                result.push_back({ 0, true });
                while (*p == '?') p++;
            }
            else
            {
                char hex[3] = { p[0], p[1], 0 };
                result.push_back({ (uint8_t)strtoul(hex, nullptr, 16), false });
                p += 2;
            }
        }
        return result;
    }

    // Scan a memory region for a pattern
    inline uintptr_t ScanRegion(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern)
    {
        if (pattern.empty() || size < pattern.size())
            return 0;

        const size_t scanEnd = size - pattern.size();

        for (size_t i = 0; i <= scanEnd; i++)
        {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); j++)
            {
                if (!pattern[j].wildcard)
                {
                    uint8_t byte = *reinterpret_cast<uint8_t*>(start + i + j);
                    if (byte != pattern[j].value)
                    {
                        found = false;
                        break;
                    }
                }
            }

            if (found)
                return start + i;
        }
        return 0;
    }

    // Scan the main module for a pattern
    inline uintptr_t FindPattern(const char* pattern, const char* label = "")
    {
        HMODULE hModule = GetModuleHandleA(nullptr);
        if (!hModule)
            return 0;

        MODULEINFO modInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
        {
            // Fallback: parse PE headers manually
            auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
            auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)hModule + dosHeader->e_lfanew);
            modInfo.lpBaseOfDll = hModule;
            modInfo.SizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        }

        auto parsed = ParsePattern(pattern);
        uintptr_t result = ScanRegion(
            reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll),
            modInfo.SizeOfImage,
            parsed
        );

        if (label && label[0])
        {
            if (result)
                LOG_INFO("PatternScan", "Found [%s] at 0x%p (RVA: 0x%llX)", label, (void*)result,
                    result - reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll));
            else
                LOG_WARN("PatternScan", "Pattern [%s] NOT FOUND", label);
        }

        return result;
    }

    // Scan a specific module for a pattern
    inline uintptr_t FindPatternInModule(HMODULE hModule, const char* pattern, const char* label = "")
    {
        if (!hModule)
            return 0;

        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;

        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)hModule + dosHeader->e_lfanew);

        auto parsed = ParsePattern(pattern);
        uintptr_t result = ScanRegion(
            reinterpret_cast<uintptr_t>(hModule),
            ntHeaders->OptionalHeader.SizeOfImage,
            parsed
        );

        if (label && label[0])
        {
            if (result)
                LOG_INFO("PatternScan", "Found [%s] at 0x%p", label, (void*)result);
            else
                LOG_WARN("PatternScan", "Pattern [%s] NOT FOUND in module", label);
        }

        return result;
    }

    // Find all occurrences of a pattern
    inline std::vector<uintptr_t> FindAllPatterns(const char* pattern, const char* label = "")
    {
        std::vector<uintptr_t> results;

        HMODULE hModule = GetModuleHandleA(nullptr);
        if (!hModule)
            return results;

        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)hModule + dosHeader->e_lfanew);

        auto parsed = ParsePattern(pattern);
        uintptr_t base = reinterpret_cast<uintptr_t>(hModule);
        size_t imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        size_t offset = 0;

        while (offset < imageSize - parsed.size())
        {
            uintptr_t found = ScanRegion(base + offset, imageSize - offset, parsed);
            if (!found)
                break;

            results.push_back(found);
            offset = (found - base) + 1;
        }

        if (label && label[0])
        {
            LOG_INFO("PatternScan", "Found %zu occurrences of [%s]", results.size(), label);
        }

        return results;
    }

    // Write bytes at address with VirtualProtect
    inline bool PatchBytes(uintptr_t address, const void* data, size_t size)
    {
        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_ERROR("Patch", "VirtualProtect failed at 0x%p (error: %lu)", (void*)address, GetLastError());
            return false;
        }

        memcpy(reinterpret_cast<void*>(address), data, size);

        VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), size);
        return true;
    }

    // NOP a range of bytes
    inline bool NopBytes(uintptr_t address, size_t count)
    {
        std::vector<uint8_t> nops(count, 0x90);
        return PatchBytes(address, nops.data(), count);
    }

    // Patch a function to return true (mov al, 1; ret)
    inline bool PatchReturnTrue(uintptr_t address)
    {
        // mov al, 1 ; ret
        uint8_t patch[] = { 0xB0, 0x01, 0xC3 };
        return PatchBytes(address, patch, sizeof(patch));
    }

    // Patch a function to return false (xor eax, eax; ret)
    inline bool PatchReturnFalse(uintptr_t address)
    {
        // xor eax, eax ; ret
        uint8_t patch[] = { 0x31, 0xC0, 0xC3 };
        return PatchBytes(address, patch, sizeof(patch));
    }

    // Patch a function to simply return (ret)
    inline bool PatchReturnVoid(uintptr_t address)
    {
        uint8_t patch[] = { 0xC3 };
        return PatchBytes(address, patch, sizeof(patch));
    }

    // Read original bytes before patching (for backup/restore)
    inline std::vector<uint8_t> ReadBytes(uintptr_t address, size_t count)
    {
        std::vector<uint8_t> result(count);
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(address), count, PAGE_EXECUTE_READ, &oldProtect);
        memcpy(result.data(), reinterpret_cast<void*>(address), count);
        VirtualProtect(reinterpret_cast<void*>(address), count, oldProtect, &oldProtect);
        return result;
    }

    // Resolve a relative call/jump target
    inline uintptr_t ResolveRelativeAddress(uintptr_t instructionAddr, int32_t instrLen)
    {
        int32_t relOffset = *reinterpret_cast<int32_t*>(instructionAddr + instrLen - 4);
        return instructionAddr + instrLen + relOffset;
    }

    struct ModuleInfo
    {
        uintptr_t base;
        size_t    size;
        char      name[MAX_PATH];
    };

    inline ModuleInfo GetMainModuleInfo()
    {
        ModuleInfo info = {};
        HMODULE hModule = GetModuleHandleA(nullptr);
        if (hModule)
        {
            info.base = reinterpret_cast<uintptr_t>(hModule);
            auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
            auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(info.base + dosHeader->e_lfanew);
            info.size = ntHeaders->OptionalHeader.SizeOfImage;
            GetModuleFileNameA(hModule, info.name, MAX_PATH);
        }
        return info;
    }
}
