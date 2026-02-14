// dllmain.cpp : Exports all ConfigDB (.db) files from Wuthering Waves
// Injects into the game process and uses the game's own SQLite API to read & export data.

#include "pch.h"

// Save and undefine Windows macros that conflict with SDK symbol names
#pragma push_macro("CopyFile")
#pragma push_macro("DeleteFile")
#pragma push_macro("MoveFile")
#pragma push_macro("GetObject")
#pragma push_macro("DrawText")
#undef CopyFile
#undef DeleteFile
#undef MoveFile
#undef GetObject
#undef DrawText

#include "SDK.hpp"

// Restore Windows macros for our own Win32 calls
#pragma pop_macro("DrawText")
#pragma pop_macro("GetObject")
#pragma pop_macro("MoveFile")
#pragma pop_macro("DeleteFile")
#pragma pop_macro("CopyFile")

#include <string>
#include <vector>
#include <cstdio>

using namespace SDK;

// ========================================================================
// SDK Utility Implementations (required by Dumper-7 generated SDK)
// ========================================================================
namespace SDK
{

namespace InSDKUtils
{
    uintptr_t GetImageBase()
    {
        static uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(NULL));
        return base;
    }
}

namespace BasicFilesImpleUtils
{
    UClass* FindClassByName(const std::string& Name, bool bByFullName)
    {
        if (bByFullName)
            return FindClassByFullName(Name);

        auto* GObj = UObject::GObjects.GetTypedPtr();
        if (!GObj) return nullptr;

        for (int32 i = 0; i < GObj->Num(); i++)
        {
            UObject* Obj = GObj->GetByIndex(i);
            if (!Obj || !Obj->Class) continue;
            if (!(Obj->Class->CastFlags & EClassCastFlags::Class)) continue;
            if (Obj->GetName() == Name)
                return static_cast<UClass*>(Obj);
        }
        return nullptr;
    }

    UClass* FindClassByFullName(const std::string& Name)
    {
        auto* GObj = UObject::GObjects.GetTypedPtr();
        if (!GObj) return nullptr;

        for (int32 i = 0; i < GObj->Num(); i++)
        {
            UObject* Obj = GObj->GetByIndex(i);
            if (!Obj || !Obj->Class) continue;
            if (!(Obj->Class->CastFlags & EClassCastFlags::Class)) continue;
            if (Obj->GetFullName() == Name)
                return static_cast<UClass*>(Obj);
        }
        return nullptr;
    }

    std::string GetObjectName(UClass* Class)
    {
        return Class ? Class->GetName() : "";
    }

    int32 GetObjectIndex(UClass* Class)
    {
        return Class ? Class->Index : 0;
    }

    uint64 GetObjFNameAsUInt64(UClass* Class)
    {
        if (!Class) return 0;
        // FName is 12 bytes, copy first 8 bytes as uint64 identifier
        uint64 result = 0;
        memcpy(&result, &Class->Name, sizeof(uint64));
        return result;
    }

    UObject* GetObjectByIndex(int32 Index)
    {
        return UObject::GObjects->GetByIndex(Index);
    }

    UFunction* FindFunctionByFName(const FName* Name)
    {
        if (!Name) return nullptr;
        auto* GObj = UObject::GObjects.GetTypedPtr();
        if (!GObj) return nullptr;

        for (int32 i = 0; i < GObj->Num(); i++)
        {
            UObject* Obj = GObj->GetByIndex(i);
            if (!Obj || !Obj->Class) continue;
            if ((Obj->Class->CastFlags & EClassCastFlags::Function) && Obj->Name == *Name)
                return static_cast<UFunction*>(Obj);
        }
        return nullptr;
    }

    FName StringToName(const wchar_t* NameStr)
    {
        // Convert wide string to UTF-8, then search GObjects for an object with matching name
        if (!NameStr) return FName();

        std::string targetUtf8 = UtfN::Utf16StringToUtf8String<std::string>(NameStr, static_cast<int>(wcslen(NameStr)));

        auto* GObj = UObject::GObjects.GetTypedPtr();
        if (!GObj) return FName();

        for (int32 i = 0; i < GObj->Num(); i++)
        {
            UObject* Obj = GObj->GetByIndex(i);
            if (!Obj) continue;
            if (Obj->Name.GetRawString() == targetUtf8)
                return Obj->Name;
        }
        return FName();
    }
}

const FName& GetStaticName(const wchar_t* NameStr, FName& StaticNameRef)
{
    if (StaticNameRef.IsNone())
    {
        StaticNameRef = BasicFilesImpleUtils::StringToName(NameStr);
    }
    return StaticNameRef;
}

// FWeakObjectPtr implementations
UObject* FWeakObjectPtr::Get() const
{
    if (ObjectIndex < 0) return nullptr;
    return UObject::GObjects->GetByIndex(ObjectIndex);
}

UObject* FWeakObjectPtr::operator->() const
{
    return Get();
}

bool FWeakObjectPtr::operator==(const FWeakObjectPtr& Other) const
{
    return ObjectIndex == Other.ObjectIndex && ObjectSerialNumber == Other.ObjectSerialNumber;
}

bool FWeakObjectPtr::operator!=(const FWeakObjectPtr& Other) const
{
    return !(*this == Other);
}

bool FWeakObjectPtr::operator==(const UObject* Other) const
{
    return Get() == Other;
}

bool FWeakObjectPtr::operator!=(const UObject* Other) const
{
    return Get() != Other;
}

} // namespace SDK

// ========================================================================
// Logging
// ========================================================================
static FILE* g_logFile = nullptr;

static void Log(const char* fmt, ...)
{
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    printf("[WuwaExport] %s\n", buf);

    if (g_logFile)
    {
        fprintf(g_logFile, "%s\n", buf);
        fflush(g_logFile);
    }
}

// ========================================================================
// Utility helpers
// ========================================================================

// Normalize UE4 forward-slash paths to Windows backslash paths
static std::wstring NormalizePath(const std::wstring& path)
{
    std::wstring result = path;
    for (auto& c : result)
    {
        if (c == L'/') c = L'\\';
    }
    return result;
}

// Recursively create directories
static void CreateDirRecursive(const std::wstring& path)
{
    std::wstring normalized = NormalizePath(path);
    size_t pos = 0;
    while ((pos = normalized.find(L'\\', pos + 1)) != std::wstring::npos)
    {
        CreateDirectoryW(normalized.substr(0, pos).c_str(), NULL);
    }
    CreateDirectoryW(normalized.c_str(), NULL);
}

// Get output directory on Desktop
static std::wstring GetOutputDir()
{
    wchar_t userProfile[MAX_PATH] = {};
    GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);
    return std::wstring(userProfile) + L"\\Desktop\\WuwaDBExport";
}

// Probe GObjects - returns object count or -1 on access violation
static int ProbeGObjectsSafe()
{
    __try
    {
        auto* GObj = SDK::UObject::GObjects.GetTypedPtr();
        if (GObj) return GObj->Num();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return -1;
}

// Wait for the game's UObject system to initialize
static bool WaitForSDK(int timeoutSeconds)
{
    for (int i = 0; i < timeoutSeconds * 2; i++)
    {
        Sleep(500);
        int count = ProbeGObjectsSafe();
        if (count > 5000)
        {
            Log("GObjects ready (%d objects). Waiting for game to stabilize...", count);
            Sleep(15000);
            return true;
        }
    }
    return false;
}

// ========================================================================
// Database file extraction via UE4 virtual filesystem
// ========================================================================

// Mount PAK helpers — isolated in SEH-safe functions (no C++ objects)
static bool TryMountGamePaks()
{
    __try { UKuroPakMountStatic::MountGamePaks(); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool TryMountMultiLangPaks()
{
    __try { UKuroPakMountStatic::MountMultiLangPaks(); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// MountPak wrapper — MountPak + RemoveSha1Check
static bool MountSinglePak(const wchar_t* path)
{
    FString fPath(path);
    UKuroPakMountStatic::MountPak(fPath, 100);
    UKuroPakMountStatic::RemoveSha1Check(fPath);
    return true;
}

// Scan a directory recursively for pakchunk*.pak files
static void FindPakFiles(const std::wstring& dir, std::vector<std::wstring>& results)
{
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do
    {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;

        std::wstring fullPath = dir + L"\\" + name;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            FindPakFiles(fullPath, results);
        }
        else
        {
            // Match pakchunk*.pak (case-insensitive)
            std::wstring lower = name;
            for (auto& c : lower) c = towlower(c);
            if (lower.size() > 12 && lower.substr(0, 8) == L"pakchunk" && lower.substr(lower.size() - 4) == L".pak")
            {
                results.push_back(fullPath);
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

// Mount all pakchunk*.pak files found under the Client directory
static void MountAllPakChunks()
{
    // Derive Client dir from content dir:
    // Content = .../Client/Content/  ->  Client = .../Client
    FString contentDirFS = UKismetSystemLibrary::GetProjectContentDirectory();
    std::wstring contentDir = contentDirFS.ToWString();
    // Normalize to backslashes and remove trailing slash
    std::wstring clientDir = contentDir;
    for (auto& c : clientDir) if (c == L'/') c = L'\\';
    while (!clientDir.empty() && clientDir.back() == L'\\') clientDir.pop_back();
    // Go up from Content to Client
    size_t pos = clientDir.find_last_of(L'\\');
    if (pos != std::wstring::npos)
        clientDir = clientDir.substr(0, pos);

    Log("Scanning for PAK files in: %ls", clientDir.c_str());

    std::vector<std::wstring> pakFiles;
    FindPakFiles(clientDir, pakFiles);

    Log("Found %d pakchunk*.pak file(s)", static_cast<int>(pakFiles.size()));

    int mounted = 0;
    for (const auto& pakPath : pakFiles)
    {
        if (MountSinglePak(pakPath.c_str()))
        {
            mounted++;
        }
        else
        {
            Log("  FAILED to mount: %ls", pakPath.c_str());
        }
    }
    Log("Mounted %d / %d PAK files", mounted, static_cast<int>(pakFiles.size()));
}

// ========================================================================
// Main export orchestration
// ========================================================================
static void ExportAllDatabases()
{
    std::wstring outputDir = GetOutputDir();
    CreateDirRecursive(outputDir);

    // Open log file
    std::wstring logPath = outputDir + L"\\export_log.txt";
    _wfopen_s(&g_logFile, logPath.c_str(), L"w");

    Log("===============================================");
    Log("  Wuthering Waves ConfigDB Export Tool");
    Log("===============================================");
    Log("Output: %ls", outputDir.c_str());

    // Get content directory from UE4 engine
    FString contentDirFS = UKismetSystemLibrary::GetProjectContentDirectory();
    std::wstring contentDirW = contentDirFS.ToWString();
    std::string contentDirUtf8 = contentDirFS.ToString();

    Log("Content directory: %s", contentDirUtf8.c_str());

    // Mount PAKs once (before processing any locale)
    {
        std::wstring dbDirUE = contentDirW;
        if (!dbDirUE.empty() && dbDirUE.back() != L'/' && dbDirUE.back() != L'\\')
            dbDirUE += L'/';
        dbDirUE += L"Aki/ConfigDB/zh-Hans";
        FString fDbDir(dbDirUE.c_str());
        FString fExt(L"db");
        TArray<FString> probe = UKuroStaticLibrary::FindFilesSorted(fDbDir, fExt);
        Log("Initial probe: %d file(s)", probe.Num());
    }

    Log("Mounting PAK archives...");
    if (TryMountGamePaks()) Log("  MountGamePaks() OK");
    else Log("  MountGamePaks() failed (exception)");

    if (TryMountMultiLangPaks()) Log("  MountMultiLangPaks() OK");
    else Log("  MountMultiLangPaks() failed (exception)");

    MountAllPakChunks();

    // Define locales to export
    struct LocaleInfo {
        const wchar_t* subdir;   // e.g. "zh-Hans", "en"
        const wchar_t* label;    // display name
        const wchar_t* outName;  // output folder name
    };
    LocaleInfo locales[] = {
        { L"zh-Hans", L"Chinese (zh-Hans)", L"zh-Hans" },
        { L"en",      L"English (en)",      L"en"      },
    };

    int totalSuccess = 0;

    for (const auto& locale : locales)
    {
        Log("");
        Log("-----------------------------------------------");
        Log("  Locale: %ls", locale.label);
        Log("-----------------------------------------------");

        // Build UE4 path for this locale
        std::wstring dbDirUE = contentDirW;
        if (!dbDirUE.empty() && dbDirUE.back() != L'/' && dbDirUE.back() != L'\\')
            dbDirUE += L'/';
        dbDirUE += L"Aki/ConfigDB/";
        dbDirUE += locale.subdir;

        Log("DB directory: %ls", dbDirUE.c_str());

        // Create locale output subdirectory
        std::wstring localeOutputDir = outputDir + L"\\" + locale.outName;
        CreateDirRecursive(localeOutputDir);

        // Enumerate files
        FString fDbDir(dbDirUE.c_str());
        FString fExt(L"db");
        TArray<FString> ueFiles = UKuroStaticLibrary::FindFilesSorted(fDbDir, fExt);
        Log("Found %d file(s)", ueFiles.Num());

        int successCount = 0;
        int failCount = 0;

        for (int32 i = 0; i < ueFiles.Num(); i++)
        {
            std::wstring ueFilePath = ueFiles[i].ToWString();

            size_t lastSlash = ueFilePath.find_last_of(L"/\\");
            std::wstring fileName = (lastSlash != std::wstring::npos)
                ? ueFilePath.substr(lastSlash + 1) : ueFilePath;

            Log("[%d/%d] %ls", i + 1, ueFiles.Num(), fileName.c_str());

            std::wstring fullPath = dbDirUE + L"/" + fileName;

            TArray<uint8> fileData;
            FString fPath(fullPath.c_str());
            bool loaded = UKuroStaticLibrary::LoadFileToArray(fPath, &fileData);

            if (!loaded || fileData.Num() == 0)
            {
                Log("  FAILED: LoadFileToArray returned empty");
                failCount++;
                continue;
            }

            std::wstring outFile = localeOutputDir + L"\\" + fileName;
            HANDLE hFile = CreateFileW(outFile.c_str(), GENERIC_WRITE, 0, NULL,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                Log("  FAILED: Cannot create output file");
                failCount++;
                continue;
            }

            DWORD written = 0;
            ::WriteFile(hFile, fileData.GetDataPtr(), static_cast<DWORD>(fileData.Num()), &written, NULL);
            CloseHandle(hFile);

            Log("  OK: %d bytes -> %ls", fileData.Num(), fileName.c_str());
            successCount++;
        }

        Log("Enumerated: %d OK, %d failed", successCount, failCount);

        Log("Locale %ls total: %d files", locale.outName, successCount);
        totalSuccess += successCount;
    }

    Log("");
    Log("Total exported across all locales: %d files", totalSuccess);

    Log("===============================================");
    Log("  Export Complete!");
    Log("  Output: %ls", outputDir.c_str());
    Log("===============================================");

    if (g_logFile)
    {
        fclose(g_logFile);
        g_logFile = nullptr;
    }
}

// ========================================================================
// Worker thread
// ========================================================================
static DWORD WINAPI WorkerThread(LPVOID)
{
    // Allocate a console window for real-time output
    AllocConsole();
    SetConsoleTitleW(L"WuwaExport - Localization DB Exporter");

    // Redirect stdout/stderr/stdin to the new console
    FILE* fOut = nullptr;
    FILE* fErr = nullptr;
    FILE* fIn  = nullptr;
    freopen_s(&fOut, "CONOUT$", "w", stdout);
    freopen_s(&fErr, "CONOUT$", "w", stderr);
    freopen_s(&fIn,  "CONIN$",  "r", stdin);

    // Bring console window to front (game may be fullscreen)
    HWND consoleWnd = GetConsoleWindow();
    if (consoleWnd)
    {
        ShowWindow(consoleWnd, SW_SHOW);
        SetForegroundWindow(consoleWnd);
    }

    printf("[WuwaExport] DLL loaded. Waiting for game to initialize...\n");

    if (!WaitForSDK(120))
    {
        printf("[WuwaExport] ERROR: Timed out waiting for SDK initialization (120s)\n");
        MessageBoxW(NULL, L"Timed out waiting for game SDK (120s).\nMake sure the game is running.", L"WuwaExport Error", MB_OK | MB_ICONERROR);
        FreeConsole();
        return 1;
    }

    printf("[WuwaExport] SDK ready. Starting database export...\n");

    ExportAllDatabases();

    printf("[WuwaExport] Done. Press Enter to close this console.\n");

    // Also show a MessageBox so user knows it's done even if console is behind game
    MessageBoxW(NULL, L"Export complete!\nOutput: Desktop\\WuwaDBExport\\", L"WuwaExport", MB_OK | MB_ICONINFORMATION);

    if (fOut) fclose(fOut);
    if (fErr) fclose(fErr);
    if (fIn)  fclose(fIn);
    FreeConsole();

    return 0;
}

// ========================================================================
// DLL Entry Point
// ========================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

