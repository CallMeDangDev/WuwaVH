#pragma once
// PakBypass.hpp - Core pak file signature bypass logic
//
// Bypasses .pak file signature checks in UE4 4.26.2 Wuthering Waves
// using STRING XREF scanning to precisely locate signature verification
// functions, avoiding false positives from generic byte patterns.
//
// Previous approach (generic patterns) crashed the game because common
// function prologues like "48 89 5C 24 ??" matched asset loading functions,
// and patching those caused "Serial size mismatch" errors.

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include "Logger.hpp"
#include "PatternScanner.hpp"
#include "EventRecorder.hpp"

// ============================================================================
// Inline hook helper (trampoline-based)
// ============================================================================
struct HookContext
{
    uintptr_t              targetAddr = 0;
    uintptr_t              detourAddr = 0;
    std::vector<uint8_t>   originalBytes;
    bool                   installed = false;
    std::string            name;
};

namespace HookEngine
{
    inline std::vector<HookContext*> g_hooks;

    // Install a 14-byte absolute jump hook (x64)
    inline bool InstallHook(HookContext& ctx, uintptr_t target, uintptr_t detour)
    {
        if (ctx.installed)
            return true;

        ctx.targetAddr = target;
        ctx.detourAddr = detour;

        // Save original bytes (14 bytes for absolute jump)
        ctx.originalBytes = PatternScanner::ReadBytes(target, 14);

        // Write: FF 25 00 00 00 00 [8-byte address]  (jmp qword ptr [rip+0])
        uint8_t jumpPatch[14] = { 0 };
        jumpPatch[0] = 0xFF;
        jumpPatch[1] = 0x25;
        jumpPatch[2] = 0x00;
        jumpPatch[3] = 0x00;
        jumpPatch[4] = 0x00;
        jumpPatch[5] = 0x00;
        memcpy(&jumpPatch[6], &detour, sizeof(uintptr_t));

        if (!PatternScanner::PatchBytes(target, jumpPatch, sizeof(jumpPatch)))
        {
            LOG_ERROR("HookEngine", "Failed to install hook [%s] at 0x%p", ctx.name.c_str(), (void*)target);
            return false;
        }

        ctx.installed = true;
        g_hooks.push_back(&ctx);

        LOG_INFO("HookEngine", "Hook [%s] installed at 0x%p -> 0x%p", ctx.name.c_str(), (void*)target, (void*)detour);
        EventRecorder::Instance().RecordHookEvent(ctx.name, target, "installed");
        return true;
    }

    inline bool RemoveHook(HookContext& ctx)
    {
        if (!ctx.installed || ctx.originalBytes.empty())
            return false;

        if (!PatternScanner::PatchBytes(ctx.targetAddr, ctx.originalBytes.data(), ctx.originalBytes.size()))
        {
            LOG_ERROR("HookEngine", "Failed to remove hook [%s]", ctx.name.c_str());
            return false;
        }

        ctx.installed = false;
        LOG_INFO("HookEngine", "Hook [%s] removed", ctx.name.c_str());
        return true;
    }

    inline void RemoveAllHooks()
    {
        for (auto* hook : g_hooks)
        {
            if (hook && hook->installed)
                RemoveHook(*hook);
        }
        g_hooks.clear();
    }
}

// ============================================================================
// Pak Signature Bypass - String XREF based (safe approach)
// ============================================================================
namespace PakBypass
{
    // Patch targets
    struct PatchInfo
    {
        std::string name;
        uintptr_t   address = 0;
        bool        patched = false;
        std::vector<uint8_t> originalBytes;
    };

    // Global state
    inline std::vector<PatchInfo>  g_patches;
    inline std::atomic<bool>       g_initialized = false;
    inline std::atomic<int>        g_bypassCount = 0;

    // ========================================================================
    // Module scanning helpers
    // ========================================================================
    struct ModuleRange
    {
        uintptr_t base = 0;
        size_t    size = 0;
        const char* name = "";
    };

    inline ModuleRange GetModuleRange(HMODULE hMod, const char* name)
    {
        ModuleRange r;
        r.name = name;
        if (!hMod) return r;

        r.base = reinterpret_cast<uintptr_t>(hMod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(r.base);
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(r.base + dos->e_lfanew);
        r.size = nt->OptionalHeader.SizeOfImage;
        return r;
    }

    // ========================================================================
    // Find a wide string in the module's data/rdata sections
    // Returns the VA of the string in memory
    // ========================================================================
    inline uintptr_t FindWideString(const ModuleRange& mod, const wchar_t* str)
    {
        size_t strLen = (wcslen(str) + 1) * sizeof(wchar_t);
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;

            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;
            if (secSize < strLen) continue;

            for (size_t offset = 0; offset <= secSize - strLen; offset += 2)
            {
                if (memcmp(reinterpret_cast<void*>(secStart + offset), str, strLen) == 0)
                    return secStart + offset;
            }
        }
        return 0;
    }

    // Find ALL occurrences of a wide string
    inline std::vector<uintptr_t> FindAllWideStrings(const ModuleRange& mod, const wchar_t* str)
    {
        std::vector<uintptr_t> results;
        size_t strLen = (wcslen(str) + 1) * sizeof(wchar_t);
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;
            if (secSize < strLen) continue;

            for (size_t offset = 0; offset <= secSize - strLen; offset += 2)
            {
                if (memcmp(reinterpret_cast<void*>(secStart + offset), str, strLen) == 0)
                    results.push_back(secStart + offset);
            }
        }
        return results;
    }

    // Find an ANSI string in the module
    inline uintptr_t FindAnsiString(const ModuleRange& mod, const char* str)
    {
        size_t strLen = strlen(str) + 1;
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;
            if (secSize < strLen) continue;

            for (size_t offset = 0; offset <= secSize - strLen; offset++)
            {
                if (memcmp(reinterpret_cast<void*>(secStart + offset), str, strLen) == 0)
                    return secStart + offset;
            }
        }
        return 0;
    }

    // Find ALL occurrences of an ANSI string
    inline std::vector<uintptr_t> FindAllAnsiStrings(const ModuleRange& mod, const char* str)
    {
        std::vector<uintptr_t> results;
        size_t strLen = strlen(str) + 1;
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;
            if (secSize < strLen) continue;

            for (size_t offset = 0; offset <= secSize - strLen; offset++)
            {
                if (memcmp(reinterpret_cast<void*>(secStart + offset), str, strLen) == 0)
                    results.push_back(secStart + offset);
            }
        }
        return results;
    }

    // ========================================================================
    // Partial/substring string search (no null terminator match)
    // Useful to find strings embedded in larger strings
    // ========================================================================
    inline std::vector<uintptr_t> FindAnsiSubstring(const ModuleRange& mod, const char* str)
    {
        std::vector<uintptr_t> results;
        size_t strLen = strlen(str); // NO +1, don't match null terminator
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;
            if (secSize < strLen) continue;

            for (size_t offset = 0; offset <= secSize - strLen; offset++)
            {
                if (memcmp(reinterpret_cast<void*>(secStart + offset), str, strLen) == 0)
                    results.push_back(secStart + offset);
            }
        }
        return results;
    }

    inline std::vector<uintptr_t> FindWideSubstring(const ModuleRange& mod, const wchar_t* str)
    {
        std::vector<uintptr_t> results;
        size_t strLen = wcslen(str) * sizeof(wchar_t); // NO null terminator
        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;
            if (secSize < strLen) continue;

            for (size_t offset = 0; offset <= secSize - strLen; offset += 2)
            {
                if (memcmp(reinterpret_cast<void*>(secStart + offset), str, strLen) == 0)
                    results.push_back(secStart + offset);
            }
        }
        return results;
    }

    // ========================================================================
    // Find all code references (LEA) to a string address
    // Scans .text section for LEA reg, [rip+disp32] instructions
    // ========================================================================
    inline std::vector<uintptr_t> FindStringXrefs(const ModuleRange& mod, uintptr_t stringAddr)
    {
        std::vector<uintptr_t> results;

        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;
            if (secSize < 7) continue;

            for (size_t offset = 0; offset < secSize - 7; offset++)
            {
                uintptr_t instrAddr = secStart + offset;
                uint8_t* code = reinterpret_cast<uint8_t*>(instrAddr);

                bool isLea = false;
                int instrLen = 0;

                // LEA with REX.W=1 (48 8D xx)
                if (code[0] == 0x48 && code[1] == 0x8D)
                {
                    uint8_t modrm = code[2];
                    if ((modrm & 0xC7) == 0x05)
                    {
                        isLea = true;
                        instrLen = 7;
                    }
                }
                // LEA with REX.WR (4C 8D xx) - for R8-R15
                else if (code[0] == 0x4C && code[1] == 0x8D)
                {
                    uint8_t modrm = code[2];
                    if ((modrm & 0xC7) == 0x05)
                    {
                        isLea = true;
                        instrLen = 7;
                    }
                }

                if (isLea)
                {
                    int32_t disp = *reinterpret_cast<int32_t*>(instrAddr + 3);
                    uintptr_t target = instrAddr + instrLen + disp;

                    if (target == stringAddr)
                        results.push_back(instrAddr);
                }
            }
        }
        return results;
    }

    // ========================================================================
    // Validate that an address looks like a real x64 function prologue
    // This prevents patching the middle of a function
    // ========================================================================
    inline bool IsValidPrologue(uintptr_t addr)
    {
        uint8_t* code = reinterpret_cast<uint8_t*>(addr);

        // Common MSVC x64 function prologues:
        // Pattern 1: mov [rsp+XX],rbx = 48 89 5C 24 XX
        // Pattern 2: mov [rsp+XX],rcx = 48 89 4C 24 XX (save first param)
        // Pattern 3: push rbx = 40 53  or  push rbp = 40 55  etc.
        // Pattern 4: sub rsp,XX = 48 83 EC XX or 48 81 EC XX XX XX XX
        // Pattern 5: push rbp = 55  (without REX prefix)
        // Pattern 6: mov rax,rsp = 48 8B C4 (save rsp to rax, common prologue)
        // Pattern 7: int 3 alignment followed by function = CC ... then prologue

        // Must match SPECIFIC prologue patterns, not just "starts with 0x48"

        // 48 89 5C 24 XX - mov [rsp+XX], rbx
        if (code[0] == 0x48 && code[1] == 0x89 && code[2] == 0x5C && code[3] == 0x24)
            return true;

        // 48 89 4C 24 XX - mov [rsp+XX], rcx (save first arg)
        if (code[0] == 0x48 && code[1] == 0x89 && code[2] == 0x4C && code[3] == 0x24)
            return true;

        // 48 89 54 24 XX - mov [rsp+XX], rdx
        if (code[0] == 0x48 && code[1] == 0x89 && code[2] == 0x54 && code[3] == 0x24)
            return true;

        // 48 89 74 24 XX - mov [rsp+XX], rsi
        if (code[0] == 0x48 && code[1] == 0x89 && code[2] == 0x74 && code[3] == 0x24)
            return true;

        // 4C 89 44 24 XX - mov [rsp+XX], r8
        if (code[0] == 0x4C && code[1] == 0x89 && code[2] == 0x44 && code[3] == 0x24)
            return true;

        // 40 53 - push rbx (with REX)
        if (code[0] == 0x40 && code[1] == 0x53)
            return true;

        // 40 55 - push rbp (with REX)
        if (code[0] == 0x40 && code[1] == 0x55)
            return true;

        // 40 56 - push rsi (with REX)
        if (code[0] == 0x40 && code[1] == 0x56)
            return true;

        // 40 57 - push rdi (with REX)
        if (code[0] == 0x40 && code[1] == 0x57)
            return true;

        // 55 - push rbp (classic)
        if (code[0] == 0x55 && (code[1] == 0x48 || code[1] == 0x41 || code[1] == 0x8B))
            return true;

        // 53 - push rbx (classic), followed by 48 or 41
        if (code[0] == 0x53 && (code[1] == 0x48 || code[1] == 0x41 || code[1] == 0x56))
            return true;

        // 48 83 EC XX - sub rsp, imm8
        if (code[0] == 0x48 && code[1] == 0x83 && code[2] == 0xEC)
            return true;

        // 48 81 EC XX XX XX XX - sub rsp, imm32
        if (code[0] == 0x48 && code[1] == 0x81 && code[2] == 0xEC)
            return true;

        // 48 8B C4 - mov rax, rsp (save stack pointer, common in large functions)
        if (code[0] == 0x48 && code[1] == 0x8B && code[2] == 0xC4)
            return true;

        // 41 54 - push r12
        if (code[0] == 0x41 && code[1] == 0x54)
            return true;

        // 41 55 - push r13
        if (code[0] == 0x41 && code[1] == 0x55)
            return true;

        // 41 56 - push r14
        if (code[0] == 0x41 && code[1] == 0x56)
            return true;

        // 41 57 - push r15
        if (code[0] == 0x41 && code[1] == 0x57)
            return true;

        return false;
    }

    // ========================================================================
    // Find all CALL (E8 rel32) instructions in executable sections
    // that target a specific address. Used to find callers of a function.
    // ========================================================================
    inline std::vector<uintptr_t> FindCallsTo(const ModuleRange& mod, uintptr_t targetAddr)
    {
        std::vector<uintptr_t> results;

        auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod.base);
        auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(mod.base + dosHeader->e_lfanew);
        auto* section = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            // Only scan executable sections
            if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            uintptr_t secStart = mod.base + section->VirtualAddress;
            size_t secSize = section->Misc.VirtualSize;

            for (size_t offset = 0; offset + 5 <= secSize; offset++)
            {
                uint8_t* code = reinterpret_cast<uint8_t*>(secStart + offset);
                if (code[0] == 0xE8) // Near CALL rel32
                {
                    int32_t rel32 = *reinterpret_cast<int32_t*>(code + 1);
                    uintptr_t callTarget = (secStart + offset) + 5 + static_cast<intptr_t>(rel32);
                    if (callTarget == targetAddr)
                    {
                        results.push_back(secStart + offset);
                    }
                }
            }
        }

        return results;
    }

    // ========================================================================
    // Walk backwards from a code reference to find the function start
    // Now with STRICT prologue validation
    // ========================================================================
    inline uintptr_t FindFunctionStart(uintptr_t codeAddr, size_t maxSearch = 2048)
    {
        for (size_t back = 0; back < maxSearch; back++)
        {
            uintptr_t addr = codeAddr - back;

            if (back > 0)
            {
                uint8_t prevByte = *reinterpret_cast<uint8_t*>(addr - 1);

                // Previous function ended with RET (C3) or INT3 (CC)
                if (prevByte == 0xCC || prevByte == 0xC3)
                {
                    if (IsValidPrologue(addr))
                    {
                        LOG_DEBUG("PakBypass", "  Function start: 0x%p (-%zu bytes, after 0x%02X, prologue validated)",
                            (void*)addr, back, prevByte);
                        return addr;
                    }
                }

                // Multiple CC padding (alignment)
                if (back > 2)
                {
                    uint8_t prev2 = *reinterpret_cast<uint8_t*>(addr - 2);
                    if (prevByte == 0xCC && prev2 == 0xCC)
                    {
                        if (IsValidPrologue(addr))
                        {
                            LOG_DEBUG("PakBypass", "  Function start: 0x%p (-%zu bytes, after CC padding, prologue validated)",
                                (void*)addr, back);
                            return addr;
                        }
                    }
                }
            }
        }

        return 0;
    }

    // ========================================================================
    // Safe patch: only patch a function if verified by string xref AND
    // the address passes prologue validation
    // ========================================================================
    inline bool SafePatchFunction(const char* name, uintptr_t funcAddr,
                                   bool returnTrue = true)
    {
        PatchInfo info;
        info.name = name;
        info.address = funcAddr;

        // CRITICAL: Validate this is actually a function start, not mid-function!
        if (!IsValidPrologue(funcAddr))
        {
            LOG_WARN("PakBypass", "[%s] REJECTED 0x%p - not a valid function prologue!", name, (void*)funcAddr);

            auto bytes = PatternScanner::ReadBytes(funcAddr, 16);
            Logger::Instance().LogHex(LogLevel::WARN, "PakBypass",
                bytes.data(), bytes.size(), "Rejected bytes (not a prologue)");

            EventRecorder::Instance().RecordBypassEvent(name, false, "not a valid prologue");
            return false;
        }

        // Save original bytes
        info.originalBytes = PatternScanner::ReadBytes(funcAddr, 16);

        LOG_INFO("PakBypass", "[%s] Patching at 0x%p (RVA: 0x%llX)",
            name, (void*)funcAddr,
            (unsigned long long)(funcAddr - GetModuleRange(GetModuleHandleA(nullptr), "").base));
        Logger::Instance().LogHex(LogLevel::DBG, "PakBypass",
            info.originalBytes.data(), info.originalBytes.size(), "Original bytes");

        bool success = false;
        if (returnTrue)
            success = PatternScanner::PatchReturnTrue(funcAddr);
        else
            success = PatternScanner::PatchReturnFalse(funcAddr);

        info.patched = success;
        g_patches.push_back(info);

        if (success)
        {
            g_bypassCount++;
            LOG_INFO("PakBypass", "[%s] BYPASSED successfully (returns %s)",
                name, returnTrue ? "true" : "false");
            EventRecorder::Instance().RecordBypassEvent(name, true, returnTrue ? "returns true" : "returns false");
        }
        else
        {
            LOG_ERROR("PakBypass", "[%s] FAILED to patch", name);
            EventRecorder::Instance().RecordBypassEvent(name, false, "patch write failed");
        }
        return success;
    }

    // ========================================================================
    // NOP a specific CALL or conditional jump instruction
    // ========================================================================
    inline bool NopCallAt(const char* name, uintptr_t callAddr, size_t instrSize = 5)
    {
        PatchInfo info;
        info.name = name;
        info.address = callAddr;
        info.originalBytes = PatternScanner::ReadBytes(callAddr, instrSize);

        LOG_INFO("PakBypass", "[%s] NOPing %zu bytes at 0x%p", name, instrSize, (void*)callAddr);
        Logger::Instance().LogHex(LogLevel::DBG, "PakBypass",
            info.originalBytes.data(), info.originalBytes.size(), "Original instruction");

        bool success = PatternScanner::NopBytes(callAddr, instrSize);
        info.patched = success;
        g_patches.push_back(info);

        if (success)
        {
            g_bypassCount++;
            EventRecorder::Instance().RecordBypassEvent(name, true, "call NOPed");
        }
        return success;
    }

    // ========================================================================
    // Comprehensive string scan - reports ALL found strings before patching
    // ========================================================================
    inline void ReportFoundStrings(const ModuleRange& mod)
    {
        LOG_INFO("PakBypass", "=== String Discovery Scan (no patching) ===");

        const char* ansiSearchTerms[] = {
            "signature", "Signature", "SIGNATURE",
            "SigningKey", "signing key",
            "PakSign", "PakEncrypt", "EncryptionKey",
            "FPakFile", "FPakPlatform", "PakPrecacher",
            "MountPak", "UnmountPak",
            "FIoStore", "IoDispatcher",
            "bSigned", "Signed", "Unsigned",
            "PakPriority", "PakEntry",
            "PakMounted", "PakOrder",
            "CheckSignature", "ValidateSignature",
            "SignatureError", "Signature Error",
            "Couldn't find pak signature",
            "Unable to create pak",
            "Checking pak file",
            "PakFileVerify",
            "DoSignatureCheck",
            nullptr
        };

        const wchar_t* wideSearchTerms[] = {
            L"signature", L"Signature",
            L"SigningKey", L"PakSign",
            L"FPakFile", L"FPakPlatform",
            L"MountPak", L"Signature Error",
            L"bSigned", L"Signed",
            L"PakMounted", L"PakOrder",
            L"Signature error detected",
            L"Couldn't find pak signature",
            L"Unable to create pak",
            L"Checking pak file",
            nullptr
        };

        for (int i = 0; ansiSearchTerms[i]; i++)
        {
            auto results = FindAnsiSubstring(mod, ansiSearchTerms[i]);
            if (!results.empty())
            {
                LOG_INFO("PakBypass", "  ANSI '%s': %zu occurrences", ansiSearchTerms[i], results.size());
                for (size_t j = 0; j < results.size() && j < 5; j++)
                {
                    char context[128] = {};
                    size_t contextLen = 0;
                    char* src = reinterpret_cast<char*>(results[j]);
                    for (size_t k = 0; k < 80; k++)
                    {
                        char c = src[k];
                        if (c == 0) break;
                        if (c >= 32 && c < 127)
                            context[contextLen++] = c;
                        else
                        {
                            context[contextLen++] = '.';
                            if (k > strlen(ansiSearchTerms[i]) + 20) break;
                        }
                    }
                    context[contextLen] = 0;
                    LOG_INFO("PakBypass", "    [%zu] 0x%p (RVA: 0x%llX): \"%s\"",
                        j, (void*)results[j],
                        (unsigned long long)(results[j] - mod.base), context);
                }
                if (results.size() > 5)
                    LOG_INFO("PakBypass", "    ... and %zu more", results.size() - 5);
            }
        }

        for (int i = 0; wideSearchTerms[i]; i++)
        {
            auto results = FindWideSubstring(mod, wideSearchTerms[i]);
            if (!results.empty())
            {
                LOG_INFO("PakBypass", "  WIDE '%ls': %zu occurrences", wideSearchTerms[i], results.size());
                for (size_t j = 0; j < results.size() && j < 5; j++)
                {
                    wchar_t context[80] = {};
                    wchar_t* src = reinterpret_cast<wchar_t*>(results[j]);
                    for (size_t k = 0; k < 70; k++)
                    {
                        if (src[k] == 0) break;
                        context[k] = (src[k] >= 32 && src[k] < 127) ? src[k] : L'.';
                    }
                    LOG_INFO("PakBypass", "    [%zu] 0x%p (RVA: 0x%llX): \"%ls\"",
                        j, (void*)results[j],
                        (unsigned long long)(results[j] - mod.base), context);
                }
                if (results.size() > 5)
                    LOG_INFO("PakBypass", "    ... and %zu more", results.size() - 5);
            }
        }

        LOG_INFO("PakBypass", "=== End of String Discovery ===");
    }

    // ========================================================================
    // Process string xrefs: find function start, validate, and patch
    // ========================================================================
    inline int ProcessStringXrefs(const ModuleRange& mod, uintptr_t strAddr,
                                   const char* patchName, bool returnTrue,
                                   bool patchFunction = true)
    {
        int patchCount = 0;
        auto xrefs = FindStringXrefs(mod, strAddr);
        LOG_INFO("PakBypass", "  Found %zu xrefs to this string", xrefs.size());

        for (size_t i = 0; i < xrefs.size(); i++)
        {
            LOG_INFO("PakBypass", "    Xref[%zu] at 0x%p (RVA: 0x%llX)",
                i, (void*)xrefs[i],
                (unsigned long long)(xrefs[i] - mod.base));

            auto xrefBytes = PatternScanner::ReadBytes(xrefs[i], 16);
            Logger::Instance().LogHex(LogLevel::DBG, "PakBypass",
                xrefBytes.data(), xrefBytes.size(), "Xref instruction bytes");

            uintptr_t funcStart = FindFunctionStart(xrefs[i]);
            if (!funcStart)
            {
                LOG_WARN("PakBypass", "    Could not find function start (searched 2048 bytes back)");
                continue;
            }

            size_t distance = xrefs[i] - funcStart;
            LOG_INFO("PakBypass", "    Function start at 0x%p (RVA: 0x%llX, %zu bytes before xref)",
                (void*)funcStart,
                (unsigned long long)(funcStart - mod.base), distance);

            if (distance > 4096)
            {
                LOG_WARN("PakBypass", "    Too far from xref, skipping");
                continue;
            }

            // Log function prologue bytes
            auto prologueBytes = PatternScanner::ReadBytes(funcStart, 32);
            Logger::Instance().LogHex(LogLevel::INFO, "PakBypass",
                prologueBytes.data(), prologueBytes.size(), "Function prologue");

            if (!patchFunction)
            {
                LOG_INFO("PakBypass", "    [ANALYSIS ONLY] Not patching this function");
                continue;
            }

            bool alreadyPatched = false;
            for (const auto& p : g_patches)
            {
                if (p.address == funcStart && p.patched)
                {
                    alreadyPatched = true;
                    break;
                }
            }
            if (alreadyPatched)
            {
                LOG_DEBUG("PakBypass", "    Already patched, skipping");
                continue;
            }

            char patchLabel[256];
            snprintf(patchLabel, sizeof(patchLabel), "%s_xref%zu", patchName, i);

            if (SafePatchFunction(patchLabel, funcStart, returnTrue))
                patchCount++;
        }
        return patchCount;
    }

    // ========================================================================
    // NOP a CALL instruction near a string xref
    // Instead of patching the whole function, find and NOP a CALL within it
    // This is useful for patching call sites inside functions
    // ========================================================================
    inline int NopCallsNearXref(const ModuleRange& mod, uintptr_t xrefAddr,
                                 const char* patchName, int searchBefore = 64,
                                 int searchAfter = 32)
    {
        int patchCount = 0;
        // Look for CALL (E8 xx xx xx xx) or JZ/JNZ (74/75 xx or 0F 84/85 xx xx xx xx)
        // in the vicinity of the xref

        for (int offset = -searchBefore; offset < searchAfter; offset++)
        {
            uintptr_t addr = xrefAddr + offset;
            uint8_t* code = reinterpret_cast<uint8_t*>(addr);

            // Test AL, AL (84 C0) followed by JZ rel8 (74 xx)
            if (code[0] == 0x84 && code[1] == 0xC0 && code[2] == 0x74)
            {
                // NOP the JZ instruction (2 bytes)
                char label[256];
                snprintf(label, sizeof(label), "%s_jz_at_%+d", patchName, offset);
                LOG_INFO("PakBypass", "  Found TEST AL,AL / JZ at xref%+d (0x%p)",
                    offset, (void*)addr);

                // NOP the JZ (2 bytes: 74 xx)
                if (NopCallAt(label, addr + 2, 2))
                    patchCount++;
            }

            // Test AL, AL (84 C0) followed by JNZ rel8 (75 xx) → need to force jump
            if (code[0] == 0x84 && code[1] == 0xC0 && code[2] == 0x75)
            {
                // Convert JNZ to JMP (EB xx)
                char label[256];
                snprintf(label, sizeof(label), "%s_jnz_to_jmp_%+d", patchName, offset);
                LOG_INFO("PakBypass", "  Found TEST AL,AL / JNZ at xref%+d (0x%p)",
                    offset, (void*)addr);

                PatchInfo info;
                info.name = label;
                info.address = addr + 2;
                info.originalBytes = PatternScanner::ReadBytes(addr + 2, 1);

                // Change 75 (JNZ) to EB (JMP unconditional)
                uint8_t jmpOpcode = 0xEB;
                bool success = PatternScanner::PatchBytes(addr + 2, &jmpOpcode, 1);
                info.patched = success;
                g_patches.push_back(info);

                if (success)
                {
                    patchCount++;
                    g_bypassCount++;
                    LOG_INFO("PakBypass", "  [%s] Converted JNZ to JMP", label);
                }
            }

            // Test AL, AL (84 C0) followed by JZ rel32 (0F 84 xx xx xx xx)
            if (code[0] == 0x84 && code[1] == 0xC0 && code[2] == 0x0F && code[3] == 0x84)
            {
                char label[256];
                snprintf(label, sizeof(label), "%s_jz32_at_%+d", patchName, offset);
                LOG_INFO("PakBypass", "  Found TEST AL,AL / JZ rel32 at xref%+d (0x%p)",
                    offset, (void*)addr);

                // NOP the JZ (6 bytes: 0F 84 xx xx xx xx)
                if (NopCallAt(label, addr + 2, 6))
                    patchCount++;
            }
        }
        return patchCount;
    }

    // ========================================================================
    // Phase 1: String XREF scan using strings found in the binary
    // ========================================================================
    inline int ScanModuleForSignatureChecks(const ModuleRange& mod)
    {
        int patchCount = 0;

        LOG_INFO("PakBypass", "--- Scanning module: %s (base=0x%p, size=0x%llX / %.1f MB) ---",
            mod.name, (void*)mod.base, (unsigned long long)mod.size, mod.size / (1024.0 * 1024.0));

        // Discovery scan first
        ReportFoundStrings(mod);

        // ====================================================================
        // Phase 1: Xref strings that WERE FOUND in the binary
        // Based on discovery scan results from the actual game binary
        // ====================================================================
        LOG_INFO("PakBypass", "=== Phase 1: String XREF Patching ===");

        struct StringTarget
        {
            const char* ansiStr;
            const wchar_t* wideStr;
            const char* patchName;
            bool returnTrue;
            bool patchIt;     // false = analysis only, true = patch the function
        };

        StringTarget targets[] = {
            // ---- STRINGS CONFIRMED IN BINARY (from discovery scan) ----

            // 1. "Signature Error" WIDE - error shown when pak sig check fails
            //    Found at 2 locations in .exe - these are HIGH VALUE targets
            { nullptr, L"Signature Error",
              "SignatureError_W", true, true },

            // 2. "FPakPlatformFile::Initialize" ANSI - pak system init
            //    Analysis only - we want to understand the function, not break it
            { "FPakPlatformFile::Initialize", nullptr,
              "PakPlatformInit", true, false },

            // 3. "MountPak" ANSI/WIDE - mount functions
            //    Analysis only - mounting is critical, don't break it
            { nullptr, L"MountPak",
              "MountPak_W", true, false },

            // ---- BACKGROUND VERIFY WORKER TARGETS ----
            // These use full exact strings including format specifiers
            // (FindWideString matches null terminator, so partial won't work)
            
            // "Signature error detected in container '%s' at block index '%d'"
            // Function called by PakFileVerifyWorker thread - prevents delayed crash
            { nullptr, L"Signature error detected in container '%s' at block index '%d'",
              "SigErrorInContainer_W", true, true },

            // NOTE: The following strings were DISABLED in v4.1
            // They are inside the pak mount/load pipeline, NOT standalone verify functions.
            // Patching them to return true breaks the mount flow because callers
            // expect output parameters (pak handle, file object) to be populated.
            // Crash at 0x144294624 (READ 0x701) was caused by CantFindPakSigFile patch.
            //
            // { nullptr, L"Couldn't find pak signature file '%s'",
            //   "CantFindPakSigFile_W", true, true },
            // { nullptr, L"Unable to create pak \"%s\" handle",
            //   "UnableCreatePak_W", true, true },
            // { nullptr, L"Checking pak file \"%s\". This may take a while...",
            //   "CheckingPakFile_W", true, true },

            // ---- STANDARD UE4 STRINGS (may not exist but try anyway) ----

            { "Pak chunk signature validation failed", nullptr,
              "DoSignatureCheck", true, true },

            { "Signature data not found", nullptr,
              "SignatureDataNotFound", true, true },

            { "FPakPlatformFile::DoSignatureCheck", nullptr,
              "DoSigCheck_Fn", true, true },

            { "Pak chunk hash validation failed", nullptr,
              "ChunkHashValidation", true, true },

            { "FPakFile::LoadSignatureData", nullptr,
              "LoadSignatureData_Fn", true, true },

            { "PakEncryptionKeyGuid", nullptr,
              "PakEncryptionKeyGuid", true, true },

            // Wide variants
            { nullptr, L"Pak chunk signature validation failed",
              "DoSignatureCheck_W2", true, true },

            { nullptr, L"FPakPlatformFile::DoSignatureCheck",
              "DoSigCheck_W2", true, true },
        };

        for (const auto& target : targets)
        {
            const char* displayName = target.ansiStr ? target.ansiStr : "(wide)";

            uintptr_t strAddr = 0;
            if (target.ansiStr)
                strAddr = FindAnsiString(mod, target.ansiStr);
            else if (target.wideStr)
            {
                strAddr = FindWideString(mod, target.wideStr);
                // For display
                static char wideBuf[256];
                snprintf(wideBuf, sizeof(wideBuf), "(wide) %ls", target.wideStr);
                displayName = wideBuf;
            }

            if (!strAddr)
            {
                LOG_DEBUG("PakBypass", "  String '%s' not found", displayName);
                continue;
            }

            LOG_INFO("PakBypass", "  >>> Found '%s' at 0x%p (RVA: 0x%llX) <<<",
                displayName, (void*)strAddr,
                (unsigned long long)(strAddr - mod.base));

            patchCount += ProcessStringXrefs(mod, strAddr, target.patchName,
                target.returnTrue, target.patchIt);

            // Also try `Signature Error` at other occurrences
            if (target.wideStr)
            {
                auto allOccurrences = FindAllWideStrings(mod, target.wideStr);
                for (size_t occ = 1; occ < allOccurrences.size(); occ++)
                {
                    LOG_INFO("PakBypass", "  >>> Additional occurrence at 0x%p <<<",
                        (void*)allOccurrences[occ]);
                    char label[256];
                    snprintf(label, sizeof(label), "%s_occ%zu", target.patchName, occ);
                    patchCount += ProcessStringXrefs(mod, allOccurrences[occ],
                        label, target.returnTrue, target.patchIt);
                }
            }
        }

        // ====================================================================
        // Phase 2: Targeted pattern scan (only most specific patterns)
        // These patterns were validated in UE4 4.26 and are highly specific
        // ====================================================================
        LOG_INFO("PakBypass", "=== Phase 2: Targeted Pattern Scan ===");

        struct PatternTarget
        {
            const char* name;
            const char* pattern;
            bool returnTrue;
        };

        PatternTarget patterns[] = {
            // ValidatePakSignaturesFromArray - validates chunk signature array
            // This is the main validation function called during pak mount
            { "ValidatePakSignatures_Pattern",
              "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 55 41 54 41 55 41 56 41 57 "
              "48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 05",
              true },

            // NOTE: LoadSignatureData pattern was REMOVED in v4
            // Patching it to return true left signature buffers uninitialized,
            // causing PakFileVerifyWorker to crash 13 minutes later when
            // trying to read garbage signature data (READ at 0xFFFFFFFFFFFFFFFF)
        };

        for (const auto& pt : patterns)
        {
            // Only scan main exe for patterns - pak signature functions live there
            // ShippingBase.dll has guard pages that cause ACCESS_VIOLATION during scan
            if (mod.base != (uintptr_t)GetModuleHandleA(nullptr))
            {
                LOG_DEBUG("PakBypass", "  Skipping pattern '%s' for non-main module %s", pt.name, mod.name);
                continue;
            }

            uintptr_t addr = PatternScanner::FindPattern(pt.pattern, pt.name);

            if (!addr)
            {
                LOG_DEBUG("PakBypass", "  Pattern '%s' not found in %s", pt.name, mod.name);
                continue;
            }

            LOG_INFO("PakBypass", "  Pattern '%s' found at 0x%p (RVA: 0x%llX)",
                pt.name, (void*)addr, (unsigned long long)(addr - mod.base));

            // Check if already patched
            bool alreadyPatched = false;
            for (const auto& p : g_patches)
            {
                if (p.address == addr && p.patched)
                {
                    alreadyPatched = true;
                    break;
                }
            }
            if (alreadyPatched)
            {
                LOG_DEBUG("PakBypass", "    Already patched, skipping");
                continue;
            }

            if (SafePatchFunction(pt.name, addr, pt.returnTrue))
                patchCount++;
        }

        // ====================================================================
        // Phase 3: Search for signing key delegate check
        // In UE4, if FCoreDelegates::GetPakSigningKeysDelegate is not bound,
        // signature checking is skipped entirely. Look for the delegate.
        // ====================================================================
        LOG_INFO("PakBypass", "=== Phase 3: Signing Key Delegate Analysis ===");

        // Search for "FCoreDelegates" or "GetPakSigningKeys" strings
        auto coreDelResults = FindAnsiSubstring(mod, "FCoreDelegates");
        if (!coreDelResults.empty())
        {
            LOG_INFO("PakBypass", "  Found 'FCoreDelegates' at %zu locations", coreDelResults.size());
            for (size_t i = 0; i < coreDelResults.size() && i < 5; i++)
            {
                char ctx[128] = {};
                char* src = reinterpret_cast<char*>(coreDelResults[i]);
                for (int k = 0; k < 80; k++)
                {
                    if (src[k] == 0) break;
                    ctx[k] = (src[k] >= 32 && src[k] < 127) ? src[k] : '.';
                }
                LOG_INFO("PakBypass", "    [%zu] 0x%p: \"%s\"",
                    i, (void*)coreDelResults[i], ctx);
            }
        }

        auto sigKeysResults = FindAnsiSubstring(mod, "SigningKeys");
        if (!sigKeysResults.empty())
        {
            LOG_INFO("PakBypass", "  Found 'SigningKeys' at %zu locations", sigKeysResults.size());
            for (size_t i = 0; i < sigKeysResults.size() && i < 5; i++)
            {
                char ctx[128] = {};
                char* src = reinterpret_cast<char*>(sigKeysResults[i]);
                for (int k = 0; k < 80; k++)
                {
                    if (src[k] == 0) break;
                    ctx[k] = (src[k] >= 32 && src[k] < 127) ? src[k] : '.';
                }
                LOG_INFO("PakBypass", "    [%zu] 0x%p: \"%s\"",
                    i, (void*)sigKeysResults[i], ctx);
            }
        }

        // Search for "pak" (case-sensitive) to catch Kuro-specific strings
        auto pakResults = FindAnsiSubstring(mod, "PakSig");
        if (!pakResults.empty())
        {
            LOG_INFO("PakBypass", "  Found 'PakSig' at %zu locations", pakResults.size());
            for (size_t i = 0; i < pakResults.size() && i < 10; i++)
            {
                char ctx[128] = {};
                char* src = reinterpret_cast<char*>(pakResults[i]);
                for (int k = 0; k < 80; k++)
                {
                    if (src[k] == 0) break;
                    ctx[k] = (src[k] >= 32 && src[k] < 127) ? src[k] : '.';
                }
                LOG_INFO("PakBypass", "    [%zu] 0x%p: \"%s\"",
                    i, (void*)pakResults[i], ctx);
            }
        }

        // ====================================================================
        // Phase 4: Verify Worker Neutralization
        // The background verify worker thread crashes when processing mod paks
        // because it tries to read signature data that doesn't exist.
        // The crash happens BEFORE the error handler (SigErrorInContainer) is called.
        // Strategy: Find all callers of SigErrorInContainer function.
        // Those callers are the verify loop functions. Patch them to return true
        // so the verify worker skips signature checking entirely.
        // ====================================================================
        LOG_INFO("PakBypass", "=== Phase 4: Verify Worker Neutralization ===");

        for (const auto& patch : g_patches)
        {
            if (patch.name.find("SigErrorInContainer") != std::string::npos && patch.patched)
            {
                LOG_INFO("PakBypass", "  Searching for callers of %s at 0x%p...",
                    patch.name.c_str(), (void*)patch.address);

                auto callers = FindCallsTo(mod, patch.address);
                LOG_INFO("PakBypass", "  Found %zu callers of SigErrorInContainer", callers.size());

                for (size_t ci = 0; ci < callers.size(); ci++)
                {
                    LOG_INFO("PakBypass", "    Caller[%zu] CALL at 0x%p (RVA: 0x%llX)",
                        ci, (void*)callers[ci],
                        (unsigned long long)(callers[ci] - mod.base));

                    uintptr_t funcStart = FindFunctionStart(callers[ci]);
                    if (!funcStart)
                    {
                        LOG_WARN("PakBypass", "      Could not find function start");
                        continue;
                    }

                    // Don't patch if it's SigErrorInContainer itself
                    if (funcStart == patch.address)
                    {
                        LOG_DEBUG("PakBypass", "      Skipping (self-reference)");
                        continue;
                    }

                    LOG_INFO("PakBypass", "      Caller function starts at 0x%p (RVA: 0x%llX)",
                        (void*)funcStart,
                        (unsigned long long)(funcStart - mod.base));

                    // Check if already patched
                    bool alreadyPatched = false;
                    for (const auto& p : g_patches)
                    {
                        if (p.address == funcStart && p.patched)
                        {
                            alreadyPatched = true;
                            break;
                        }
                    }
                    if (alreadyPatched)
                    {
                        LOG_DEBUG("PakBypass", "      Already patched, skipping");
                        continue;
                    }

                    char name[256];
                    snprintf(name, sizeof(name), "VerifyLoopCaller_%zu", ci);
                    if (SafePatchFunction(name, funcStart, true))
                        patchCount++;
                }
            }
        }

        // ====================================================================
        // Phase 5: REMOVED in v5.1
        // Direct crash site patching was too aggressive - the functions at
        // crash stack RVAs (0x5543CF8, 0xAD7C56, etc.) are shared utility
        // functions called from many places, not just the verify worker.
        // Patching them to return true caused black screen on game load.
        //
        // Instead, we rely on the VEH crash recovery handler in dllmain.cpp
        // which catches the specific crash pattern (READ at 0xFFFFFFFFFFFFFFFF)
        // and recovers by returning 0 to the caller. This is surgical and
        // only affects the actual crash site without breaking other callers.
        // ====================================================================
        LOG_INFO("PakBypass", "=== Phase 5: VEH Crash Recovery (active in dllmain.cpp) ===");
        LOG_INFO("PakBypass", "  Verify worker crashes will be caught and recovered by VEH handler");
        LOG_INFO("PakBypass", "  Pattern: ACCESS_VIOLATION READ at 0xFFFFFFFFFFFFFFFF -> return 0");

        return patchCount;
    }

    // ========================================================================
    // Create valid .sig files for mod paks by copying a real game .sig
    // This prevents the verify worker from crashing due to missing/empty
    // signature data. The actual hash mismatches are handled by
    // ValidatePakSignatures (patched to return true).
    // ========================================================================
    inline void CreateModSigFiles()
    {
        // Find the game's Paks directory from the executable path
        char exePath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);

        std::string paksDir = exePath;
        // Navigate from Binaries/Win64/exe to Content/Paks/
        size_t binPos = paksDir.find("Binaries");
        if (binPos == std::string::npos)
        {
            LOG_WARN("PakBypass", "CreateModSigFiles: Cannot find Binaries in exe path");
            return;
        }
        paksDir = paksDir.substr(0, binPos) + "Content\\Paks\\";
        std::string modsDir = paksDir + "~mods\\";

        LOG_INFO("PakBypass", "=== Creating .sig files for mod paks ===");
        LOG_INFO("PakBypass", "  Paks dir: %s", paksDir.c_str());
        LOG_INFO("PakBypass", "  Mods dir: %s", modsDir.c_str());

        // Find a real .sig file to use as template
        WIN32_FIND_DATAA findData;
        std::string searchPattern = paksDir + "*.sig";
        HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            LOG_WARN("PakBypass", "  No existing .sig files found in Paks dir");
            return;
        }

        // Find the smallest .sig file as template (less data to copy)
        std::string templateSig;
        DWORD smallestSize = MAXDWORD;
        do
        {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                if (findData.nFileSizeLow > 0 && findData.nFileSizeLow < smallestSize)
                {
                    smallestSize = findData.nFileSizeLow;
                    templateSig = paksDir + findData.cFileName;
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);

        if (templateSig.empty())
        {
            LOG_WARN("PakBypass", "  No valid .sig template found");
            return;
        }

        LOG_INFO("PakBypass", "  Template .sig: %s (%lu bytes)", templateSig.c_str(), smallestSize);

        // Read the template .sig content
        HANDLE hTemplate = CreateFileA(templateSig.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hTemplate == INVALID_HANDLE_VALUE)
        {
            LOG_ERROR("PakBypass", "  Failed to open template .sig");
            return;
        }

        std::vector<uint8_t> sigData(smallestSize);
        DWORD bytesRead = 0;
        ReadFile(hTemplate, sigData.data(), smallestSize, &bytesRead, nullptr);
        CloseHandle(hTemplate);

        if (bytesRead != smallestSize)
        {
            LOG_ERROR("PakBypass", "  Failed to read template .sig (read %lu of %lu)", bytesRead, smallestSize);
            return;
        }

        // Log template header
        if (sigData.size() >= 12)
        {
            uint32_t magic = *reinterpret_cast<uint32_t*>(sigData.data());
            uint32_t version = *reinterpret_cast<uint32_t*>(sigData.data() + 4);
            uint32_t field2 = *reinterpret_cast<uint32_t*>(sigData.data() + 8);
            LOG_INFO("PakBypass", "  Template header: magic=0x%08X version=%u field2=%u",
                magic, version, field2);
        }

        // Find mod .pak files and create .sig for each
        std::string modSearch = modsDir + "*.pak";
        hFind = FindFirstFileA(modSearch.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            LOG_INFO("PakBypass", "  No mod .pak files found in ~mods");
            return;
        }

        int created = 0;
        do
        {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            std::string pakName = findData.cFileName;
            // Replace .pak extension with .sig
            size_t dotPos = pakName.rfind(".pak");
            if (dotPos == std::string::npos)
                continue;

            std::string sigName = pakName.substr(0, dotPos) + ".sig";
            std::string sigPath = modsDir + sigName;

            // Check if .sig already exists and has valid content (non-empty)
            HANDLE hExisting = CreateFileA(sigPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hExisting != INVALID_HANDLE_VALUE)
            {
                DWORD existingSize = GetFileSize(hExisting, nullptr);
                CloseHandle(hExisting);
                if (existingSize >= 12) // Has at least a header
                {
                    LOG_INFO("PakBypass", "  %s: .sig exists (%lu bytes), keeping", pakName.c_str(), existingSize);
                    continue;
                }
                // Delete empty/invalid .sig
                DeleteFileA(sigPath.c_str());
                LOG_INFO("PakBypass", "  %s: removed invalid .sig (%lu bytes)", pakName.c_str(), existingSize);
            }

            // Create .sig file with template content
            HANDLE hSig = CreateFileA(sigPath.c_str(), GENERIC_WRITE, 0,
                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hSig == INVALID_HANDLE_VALUE)
            {
                LOG_ERROR("PakBypass", "  %s: failed to create .sig (error %lu)", pakName.c_str(), GetLastError());
                continue;
            }

            DWORD bytesWritten = 0;
            WriteFile(hSig, sigData.data(), (DWORD)sigData.size(), &bytesWritten, nullptr);
            CloseHandle(hSig);

            if (bytesWritten == sigData.size())
            {
                LOG_INFO("PakBypass", "  %s: created .sig (%zu bytes from template)", pakName.c_str(), sigData.size());
                created++;
            }
            else
            {
                LOG_ERROR("PakBypass", "  %s: write failed (%lu of %zu)", pakName.c_str(), bytesWritten, sigData.size());
            }

        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);

        LOG_INFO("PakBypass", "  Created %d .sig files for mod paks", created);
    }

    // ========================================================================
    // Main initialization
    // ========================================================================
    inline bool Initialize()
    {
        if (g_initialized.exchange(true))
            return true;

        LOG_INFO("PakBypass", "========================================");
        LOG_INFO("PakBypass", "  Initializing Pak Signature Bypass");
        LOG_INFO("PakBypass", "  Target: Wuthering Waves (UE4 4.26.2)");
        LOG_INFO("PakBypass", "  Method: String XREF + Pattern (v4)");
        LOG_INFO("PakBypass", "========================================");

        int totalPatches = 0;

        // ====================================================================
        // 0. Create valid .sig files for mod paks (BEFORE any scanning)
        // This prevents the verify worker from crashing due to missing/empty
        // signature data when processing mod pak files.
        // ====================================================================
        CreateModSigFiles();

        // ====================================================================
        // 1. Scan main executable
        // ====================================================================
        HMODULE hMain = GetModuleHandleA(nullptr);
        auto mainMod = GetModuleRange(hMain, "Client-Win64-Shipping.exe");

        LOG_INFO("PakBypass", "Main module: base=0x%p, size=0x%llX (%.1f MB)",
            (void*)mainMod.base, (unsigned long long)mainMod.size,
            mainMod.size / (1024.0 * 1024.0));

        EventRecorder::Instance().RecordEvent("INIT", "PakBypass_Start",
            "String XREF + Pattern v4");

        totalPatches += ScanModuleForSignatureChecks(mainMod);

        // ====================================================================
        // 2. Scan ShippingBase.dll (Kuro's custom engine code)
        // ====================================================================
        HMODULE hBase = GetModuleHandleA("Client-Win64-ShippingBase.dll");
        if (hBase)
        {
            auto baseMod = GetModuleRange(hBase, "Client-Win64-ShippingBase.dll");
            LOG_INFO("PakBypass", "ShippingBase module: base=0x%p, size=0x%llX (%.1f MB)",
                (void*)baseMod.base, (unsigned long long)baseMod.size,
                baseMod.size / (1024.0 * 1024.0));

            totalPatches += ScanModuleForSignatureChecks(baseMod);
        }
        else
        {
            LOG_WARN("PakBypass", "Client-Win64-ShippingBase.dll not found");
        }

        // ====================================================================
        // Summary
        // ====================================================================
        LOG_INFO("PakBypass", "========================================");
        LOG_INFO("PakBypass", "  Bypass initialization complete");
        LOG_INFO("PakBypass", "  Total patches applied: %d", totalPatches);
        if (totalPatches > 0)
        {
            LOG_INFO("PakBypass", "  Status: ACTIVE");
            LOG_INFO("PakBypass", "  Patched functions verified: prologue validated");
        }
        else
        {
            LOG_WARN("PakBypass", "  Status: NO PATCHES APPLIED");
            LOG_WARN("PakBypass", "  Review String Discovery + Phase 3 output for leads.");
            LOG_WARN("PakBypass", "  Kuro may have stripped all standard UE4 pak signing strings.");
            LOG_WARN("PakBypass", "  Next steps: analyze 'Signature Error' xrefs and pattern matches.");
        }
        LOG_INFO("PakBypass", "========================================");

        EventRecorder::Instance().RecordEvent("INIT", "PakBypass_Complete",
            "Patches: " + std::to_string(totalPatches));

        return totalPatches > 0;
    }

    // ========================================================================
    // Cleanup
    // ========================================================================
    inline void Shutdown()
    {
        LOG_INFO("PakBypass", "Shutting down pak bypass...");

        for (auto& patch : g_patches)
        {
            if (patch.patched && !patch.originalBytes.empty())
            {
                PatternScanner::PatchBytes(patch.address, patch.originalBytes.data(),
                    patch.originalBytes.size() > 3 ? 3 : patch.originalBytes.size());
                LOG_INFO("PakBypass", "Restored [%s] at 0x%p", patch.name.c_str(), (void*)patch.address);
            }
        }

        HookEngine::RemoveAllHooks();
        g_patches.clear();
        g_initialized = false;

        LOG_INFO("PakBypass", "Shutdown complete. Total bypass invocations: %d", g_bypassCount.load());
    }
}
