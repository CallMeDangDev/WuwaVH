// dllmain.cpp - WuWa Viet Hoa Pak Loader (version.dll proxy)
//
// Mounts translation .pak files and removes SHA1 checks using the game's SDK.
// Place as "version.dll" next to the game exe, put .pak files in "wuwaVietHoa" folder.

#include "pch.h"

#include "Logger.hpp"
#include "VersionProxy.hpp"
#include "SDK/Basic.hpp"
#include "SDK/CoreUObject_structs.hpp"
#include "SDK/CoreUObject_classes.hpp"
#include "SDK/CoreUObject_functions.cpp"
#include "SDK/Engine_structs.hpp"
#include "SDK/Engine_classes.hpp"
#include "SDK/Engine_parameters.hpp"
#include "SDK/KuroHotPatch_structs.hpp"
#include "SDK/KuroHotPatch_classes.hpp"
#include "SDK/KuroHotPatch_parameters.hpp"
#include "SDK/KuroHotPatch_functions.cpp"
#include "SDK/Basic.cpp"

namespace SDK
{
    class FName UKismetStringLibrary::Conv_StringToName(const class FString& InString)
    {
        static class UFunction* Func = nullptr;
        if (Func == nullptr)
            Func = StaticClass()->GetFunction("KismetStringLibrary", "Conv_StringToName");
        Params::KismetStringLibrary_Conv_StringToName Parms{};
        Parms.InString = std::move(InString);
        auto Flgs = Func->FunctionFlags;
        Func->FunctionFlags |= 0x400;
        GetDefaultObj()->ProcessEvent(Func, &Parms);
        Func->FunctionFlags = Flgs;
        return Parms.ReturnValue;
    }
}

namespace fs = std::filesystem;

static bool CheckMountPak()
{
    SDK::UFunction* Func = SDK::UKuroPakMountStatic::StaticClass()->GetFunction("KuroPakMountStatic", "MountPak");
    return Func != nullptr;
}

static bool ProcessPakFiles(const std::string& folderPath)
{
    if (!fs::exists(folderPath) || !fs::is_directory(folderPath))
        return false;

    int order = 46;
    bool found = false;

    Sleep(3000);

    for (const auto& entry : fs::directory_iterator(folderPath))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".pak")
        {
            found = true;
            std::wstring wpath = entry.path().wstring();

            SDK::UKuroPakMountStatic::MountPak(wpath.c_str(), order);
            SDK::UKuroPakMountStatic::RemoveSha1Check(wpath.c_str());

            LOG_INFO("Pak", "Loaded: %ls", wpath.c_str());
            order++;
        }
    }

    return found;
}

static std::string GetDllDirectory(HMODULE hModule)
{
    char buffer[MAX_PATH];
    GetModuleFileNameA(hModule, buffer, MAX_PATH);
    return fs::path(buffer).parent_path().string();
}

DWORD WINAPI MainThread(LPVOID lpParam)
{
    HMODULE hModule = reinterpret_cast<HMODULE>(lpParam);

#ifdef _DEBUG
    Logger::Instance().Initialize();
#endif

    LOG_INFO("Init", "Dang cho game khoi tao...");
    while (!CheckMountPak())
        Sleep(100);
    LOG_INFO("Init", "Game da san sang!");

    fs::path dllDir = GetDllDirectory(hModule);

    // Load export_localization_db.dll if present
    fs::path locDll = dllDir / "export_localization_db.dll";
    if (fs::exists(locDll))
    {
        HMODULE hLoc = LoadLibraryA(locDll.string().c_str());
        if (hLoc)
            LOG_INFO("Init", "Loaded: export_localization_db.dll");
        else
            LOG_WARN("Init", "export_localization_db.dll load that bai (error: %lu)", GetLastError());
    }

    fs::path pakDir = dllDir / "wuwaVietHoa";
    std::string pakPath = pakDir.string();

    if (!fs::exists(pakPath))
    {
        LOG_WARN("Init", "Tao thu muc: %s", pakPath.c_str());
        fs::create_directories(pakPath);
    }

    if (ProcessPakFiles(pakPath))
    {
        LOG_INFO("Done", "Tai thanh cong!");
    }
    else
    {
        LOG_ERROR("Done", "Khong tim thay file .pak trong: %s", pakPath.c_str());
        LOG_ERROR("Done", "Thoat game sau 5 giay...");
        Sleep(5000);
        ExitProcess(1);
    }

#ifdef _DEBUG
    Logger::Instance().Flush();
#endif
    Sleep(1000);
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        VersionProxy::LoadRealDll();
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        break;

    case DLL_PROCESS_DETACH:
        VersionProxy::Unload();
        break;
    }

    return TRUE;
}
