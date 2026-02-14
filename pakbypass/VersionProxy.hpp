#pragma once
// VersionProxy.hpp - Proxies the real version.dll for DLL injection
//
// This DLL is placed in the game directory as "version.dll" and forwards
// all original version.dll calls to the real system version.dll while
// adding our pak bypass functionality.

#include <windows.h>
#include "Logger.hpp"

namespace VersionProxy
{
    // Handle to the real version.dll
    inline HMODULE g_realVersionDll = nullptr;

    // Function pointers for all version.dll exports
    inline FARPROC g_pGetFileVersionInfoA = nullptr;
    inline FARPROC g_pGetFileVersionInfoByHandle = nullptr;
    inline FARPROC g_pGetFileVersionInfoExA = nullptr;
    inline FARPROC g_pGetFileVersionInfoExW = nullptr;
    inline FARPROC g_pGetFileVersionInfoSizeA = nullptr;
    inline FARPROC g_pGetFileVersionInfoSizeExA = nullptr;
    inline FARPROC g_pGetFileVersionInfoSizeExW = nullptr;
    inline FARPROC g_pGetFileVersionInfoSizeW = nullptr;
    inline FARPROC g_pGetFileVersionInfoW = nullptr;
    inline FARPROC g_pVerFindFileA = nullptr;
    inline FARPROC g_pVerFindFileW = nullptr;
    inline FARPROC g_pVerInstallFileA = nullptr;
    inline FARPROC g_pVerInstallFileW = nullptr;
    inline FARPROC g_pVerLanguageNameA = nullptr;
    inline FARPROC g_pVerLanguageNameW = nullptr;
    inline FARPROC g_pVerQueryValueA = nullptr;
    inline FARPROC g_pVerQueryValueW = nullptr;

    inline bool LoadRealDll()
    {
        // Get System32 path
        char systemDir[MAX_PATH];
        GetSystemDirectoryA(systemDir, MAX_PATH);

        std::string realPath = std::string(systemDir) + "\\version.dll";

        g_realVersionDll = LoadLibraryA(realPath.c_str());
        if (!g_realVersionDll)
        {
            LOG_ERROR("VersionProxy", "Failed to load real version.dll from '%s' (error: %lu)",
                realPath.c_str(), GetLastError());
            return false;
        }

        LOG_INFO("VersionProxy", "Loaded real version.dll from '%s'", realPath.c_str());

        // Resolve all exports
        g_pGetFileVersionInfoA      = GetProcAddress(g_realVersionDll, "GetFileVersionInfoA");
        g_pGetFileVersionInfoByHandle = GetProcAddress(g_realVersionDll, "GetFileVersionInfoByHandle");
        g_pGetFileVersionInfoExA    = GetProcAddress(g_realVersionDll, "GetFileVersionInfoExA");
        g_pGetFileVersionInfoExW    = GetProcAddress(g_realVersionDll, "GetFileVersionInfoExW");
        g_pGetFileVersionInfoSizeA  = GetProcAddress(g_realVersionDll, "GetFileVersionInfoSizeA");
        g_pGetFileVersionInfoSizeExA = GetProcAddress(g_realVersionDll, "GetFileVersionInfoSizeExA");
        g_pGetFileVersionInfoSizeExW = GetProcAddress(g_realVersionDll, "GetFileVersionInfoSizeExW");
        g_pGetFileVersionInfoSizeW  = GetProcAddress(g_realVersionDll, "GetFileVersionInfoSizeW");
        g_pGetFileVersionInfoW      = GetProcAddress(g_realVersionDll, "GetFileVersionInfoW");
        g_pVerFindFileA             = GetProcAddress(g_realVersionDll, "VerFindFileA");
        g_pVerFindFileW             = GetProcAddress(g_realVersionDll, "VerFindFileW");
        g_pVerInstallFileA          = GetProcAddress(g_realVersionDll, "VerInstallFileA");
        g_pVerInstallFileW          = GetProcAddress(g_realVersionDll, "VerInstallFileW");
        g_pVerLanguageNameA         = GetProcAddress(g_realVersionDll, "VerLanguageNameA");
        g_pVerLanguageNameW         = GetProcAddress(g_realVersionDll, "VerLanguageNameW");
        g_pVerQueryValueA           = GetProcAddress(g_realVersionDll, "VerQueryValueA");
        g_pVerQueryValueW           = GetProcAddress(g_realVersionDll, "VerQueryValueW");

        LOG_INFO("VersionProxy", "All version.dll exports resolved successfully");
        return true;
    }

    inline void Unload()
    {
        if (g_realVersionDll)
        {
            FreeLibrary(g_realVersionDll);
            g_realVersionDll = nullptr;
            LOG_INFO("VersionProxy", "Real version.dll unloaded");
        }
    }
}

// ============================================================================
// Exported proxy functions
// These are exported with the same names as the real version.dll functions.
// They simply forward calls to the real DLL.
// ============================================================================

extern "C"
{
    __declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
    {
        if (VersionProxy::g_pGetFileVersionInfoA)
            return reinterpret_cast<BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID)>(VersionProxy::g_pGetFileVersionInfoA)(lptstrFilename, dwHandle, dwLen, lpData);
        return FALSE;
    }

    __declspec(dllexport) int WINAPI Proxy_GetFileVersionInfoByHandle(int hMem, LPCWSTR lpFileName, HANDLE handle, LPVOID lpData, DWORD dwLen)
    {
        if (VersionProxy::g_pGetFileVersionInfoByHandle)
            return reinterpret_cast<int(WINAPI*)(int, LPCWSTR, HANDLE, LPVOID, DWORD)>(VersionProxy::g_pGetFileVersionInfoByHandle)(hMem, lpFileName, handle, lpData, dwLen);
        return 0;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
    {
        if (VersionProxy::g_pGetFileVersionInfoExA)
            return reinterpret_cast<BOOL(WINAPI*)(DWORD, LPCSTR, DWORD, DWORD, LPVOID)>(VersionProxy::g_pGetFileVersionInfoExA)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
        return FALSE;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
    {
        if (VersionProxy::g_pGetFileVersionInfoExW)
            return reinterpret_cast<BOOL(WINAPI*)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID)>(VersionProxy::g_pGetFileVersionInfoExW)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
        return FALSE;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle)
    {
        if (VersionProxy::g_pGetFileVersionInfoSizeA)
            return reinterpret_cast<DWORD(WINAPI*)(LPCSTR, LPDWORD)>(VersionProxy::g_pGetFileVersionInfoSizeA)(lptstrFilename, lpdwHandle);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle)
    {
        if (VersionProxy::g_pGetFileVersionInfoSizeExA)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPCSTR, LPDWORD)>(VersionProxy::g_pGetFileVersionInfoSizeExA)(dwFlags, lpwstrFilename, lpdwHandle);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle)
    {
        if (VersionProxy::g_pGetFileVersionInfoSizeExW)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPCWSTR, LPDWORD)>(VersionProxy::g_pGetFileVersionInfoSizeExW)(dwFlags, lpwstrFilename, lpdwHandle);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
    {
        if (VersionProxy::g_pGetFileVersionInfoSizeW)
            return reinterpret_cast<DWORD(WINAPI*)(LPCWSTR, LPDWORD)>(VersionProxy::g_pGetFileVersionInfoSizeW)(lptstrFilename, lpdwHandle);
        return 0;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
    {
        if (VersionProxy::g_pGetFileVersionInfoW)
            return reinterpret_cast<BOOL(WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID)>(VersionProxy::g_pGetFileVersionInfoW)(lptstrFilename, dwHandle, dwLen, lpData);
        return FALSE;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_VerFindFileA(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir, LPSTR szCurDir, PUINT lpuCurDirLen, LPSTR szDestDir, PUINT lpuDestDirLen)
    {
        if (VersionProxy::g_pVerFindFileA)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT)>(VersionProxy::g_pVerFindFileA)(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_VerFindFileW(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir, LPWSTR szCurDir, PUINT lpuCurDirLen, LPWSTR szDestDir, PUINT lpuDestDirLen)
    {
        if (VersionProxy::g_pVerFindFileW)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT)>(VersionProxy::g_pVerFindFileW)(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_VerInstallFileA(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT lpuTmpFileLen)
    {
        if (VersionProxy::g_pVerInstallFileA)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT)>(VersionProxy::g_pVerInstallFileA)(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, lpuTmpFileLen);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_VerInstallFileW(DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName, LPCWSTR szSrcDir, LPCWSTR szDestDir, LPCWSTR szCurDir, LPWSTR szTmpFile, PUINT lpuTmpFileLen)
    {
        if (VersionProxy::g_pVerInstallFileW)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT)>(VersionProxy::g_pVerInstallFileW)(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, lpuTmpFileLen);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang)
    {
        if (VersionProxy::g_pVerLanguageNameA)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPSTR, DWORD)>(VersionProxy::g_pVerLanguageNameA)(wLang, szLang, cchLang);
        return 0;
    }

    __declspec(dllexport) DWORD WINAPI Proxy_VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang)
    {
        if (VersionProxy::g_pVerLanguageNameW)
            return reinterpret_cast<DWORD(WINAPI*)(DWORD, LPWSTR, DWORD)>(VersionProxy::g_pVerLanguageNameW)(wLang, szLang, cchLang);
        return 0;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen)
    {
        if (VersionProxy::g_pVerQueryValueA)
            return reinterpret_cast<BOOL(WINAPI*)(LPCVOID, LPCSTR, LPVOID*, PUINT)>(VersionProxy::g_pVerQueryValueA)(pBlock, lpSubBlock, lplpBuffer, puLen);
        return FALSE;
    }

    __declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen)
    {
        if (VersionProxy::g_pVerQueryValueW)
            return reinterpret_cast<BOOL(WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT)>(VersionProxy::g_pVerQueryValueW)(pBlock, lpSubBlock, lplpBuffer, puLen);
        return FALSE;
    }
}
