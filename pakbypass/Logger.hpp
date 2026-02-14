#pragma once
// Logger.hpp - Console & file logging for WuWa Viet Hoa
// Only active in Debug builds; completely stripped in Release.

#ifdef _DEBUG

#include <windows.h>
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <cstdio>

enum class LogLevel : int
{
    INFO  = 0,
    WARN  = 1,
    ERR   = 2
};

class Logger
{
public:
    static Logger& Instance()
    {
        static Logger instance;
        return instance;
    }

    bool Initialize(const std::string& logDir = "", bool showConsole = true)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_initialized)
            return true;

        // Allocate a console window for real-time debug output
        if (showConsole)
            InitConsole();

        std::string dir = logDir;
        if (dir.empty())
        {
            char modulePath[MAX_PATH];
            GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
            dir = std::filesystem::path(modulePath).parent_path().string();
            dir += "\\pakbypass_logs";
        }

        std::filesystem::create_directories(dir);

        // Generate timestamped filename
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        struct tm tmBuf;
        localtime_s(&tmBuf, &time);

        std::ostringstream fname;
        fname << dir << "\\pakbypass_"
              << std::put_time(&tmBuf, "%Y%m%d_%H%M%S")
              << ".log";

        m_logFile.open(fname.str(), std::ios::out | std::ios::trunc);
        if (!m_logFile.is_open())
            return false;

        m_logPath = fname.str();
        m_initialized = true;

        WriteHeader();
        return true;
    }

    void SetLevel(LogLevel level)
    {
        m_level = level;
    }

    void Log(LogLevel level, const char* category, const char* fmt, ...)
    {
        if (level < m_level || !m_initialized)
            return;

        char buffer[4096];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);

        WriteEntry(level, category, buffer);
    }

    void Flush()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_logFile.is_open())
            m_logFile.flush();
    }

    void Shutdown()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_logFile.is_open())
        {
            m_logFile.flush();
            m_logFile.close();
        }
        m_initialized = false;
    }

    const std::string& GetLogPath() const { return m_logPath; }

private:
    Logger() = default;
    ~Logger() { Shutdown(); }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void WriteHeader()
    {
        m_logFile << "WuWa Viet Hoa - Log started: " << GetTimestamp() << "\n";
        m_logFile.flush();
    }

    void WriteEntry(LogLevel level, const char* category, const char* message)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Write to log file
        if (m_logFile.is_open())
        {
            m_logFile << "[" << GetTimestamp() << "] "
                      << "[" << LevelToStr(level) << "] "
                      << "[" << category << "] "
                      << message << "\n";

            // Auto-flush on warnings and above
            if (level >= LogLevel::WARN)
                m_logFile.flush();
        }

        // Write to console (always, if console is attached)
        if (m_consoleAllocated)
            PrintConsole(level, category, message);
    }

    static std::string GetTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        struct tm tmBuf;
        localtime_s(&tmBuf, &time);

        std::ostringstream oss;
        oss << std::put_time(&tmBuf, "%H:%M:%S")
            << "." << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    static const char* LevelToStr(LogLevel level)
    {
        switch (level)
        {
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERR:   return "ERROR";
        default:              return "     ";
        }
    }

    void InitConsole()
    {
        if (m_consoleAllocated)
            return;

        if (!AllocConsole())
            return;

        m_consoleAllocated = true;
        m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

        // Redirect C stdio to the new console
        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);

        SetConsoleTitleA("WuWa Viet Hoa");

        // Enable ANSI / virtual terminal if available (Windows 10+)
        DWORD consoleMode = 0;
        GetConsoleMode(m_hConsole, &consoleMode);
        SetConsoleMode(m_hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

        COORD bufferSize = { 80, 300 };
        SetConsoleScreenBufferSize(m_hConsole, bufferSize);

        SMALL_RECT windowSize = { 0, 0, 79, 20 };
        SetConsoleWindowInfo(m_hConsole, TRUE, &windowSize);

        // Print banner
        SetConsoleTextAttribute(m_hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("========================================\n");
        printf("  WuWa Viet Hoa - Pak Loader\n");
        printf("========================================\n");
        SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    void PrintConsole(LogLevel level, const char* category, const char* message)
    {
        if (!m_hConsole)
            return;

        WORD color;
        const char* prefix;
        switch (level)
        {
        case LogLevel::INFO:  color = FOREGROUND_GREEN | FOREGROUND_INTENSITY;                          prefix = "[+]"; break;
        case LogLevel::WARN:  color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;         prefix = "[!]"; break;
        case LogLevel::ERR:   color = FOREGROUND_RED | FOREGROUND_INTENSITY;                             prefix = "[-]"; break;
        default:              color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;               prefix = "[*]"; break;
        }

        SetConsoleTextAttribute(m_hConsole, color);
        printf("%s %s\n", prefix, message);
        SetConsoleTextAttribute(m_hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    std::mutex      m_mutex;
    std::ofstream   m_logFile;
    std::string     m_logPath;
    HANDLE          m_hConsole = nullptr;
    LogLevel        m_level = LogLevel::INFO;
    bool            m_initialized = false;
    bool            m_consoleAllocated = false;
};

// Convenience macros
#define LOG_INFO(cat, fmt, ...)  Logger::Instance().Log(LogLevel::INFO,  cat, fmt, ##__VA_ARGS__)
#define LOG_WARN(cat, fmt, ...)  Logger::Instance().Log(LogLevel::WARN,  cat, fmt, ##__VA_ARGS__)
#define LOG_ERROR(cat, fmt, ...) Logger::Instance().Log(LogLevel::ERR,   cat, fmt, ##__VA_ARGS__)

#else // Release build - strip all logging

#define LOG_INFO(cat, fmt, ...)  ((void)0)
#define LOG_WARN(cat, fmt, ...)  ((void)0)
#define LOG_ERROR(cat, fmt, ...) ((void)0)

#endif // _DEBUG
