#pragma once
// EventRecorder.hpp - Records game events for debugging and improvement

#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <filesystem>
#include "Logger.hpp"

struct GameEvent
{
    std::string              timestamp;
    std::string              category;
    std::string              eventName;
    std::string              details;
    uintptr_t                address = 0;
    DWORD                    threadId = 0;
    uint64_t                 tickCount = 0;
};

class EventRecorder
{
public:
    static EventRecorder& Instance()
    {
        static EventRecorder instance;
        return instance;
    }

    bool Initialize(const std::string& logDir = "")
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_initialized)
            return true;

        std::string dir = logDir;
        if (dir.empty())
        {
            char modulePath[MAX_PATH];
            GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
            dir = std::filesystem::path(modulePath).parent_path().string();
            dir += "\\pakbypass_logs";
        }

        std::filesystem::create_directories(dir);

        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        struct tm tmBuf;
        localtime_s(&tmBuf, &time);

        std::ostringstream fname;
        fname << dir << "\\events_"
              << std::put_time(&tmBuf, "%Y%m%d_%H%M%S")
              << ".csv";

        m_eventFile.open(fname.str(), std::ios::out | std::ios::trunc);
        if (!m_eventFile.is_open())
            return false;

        // CSV header
        m_eventFile << "Timestamp,TickCount,ThreadID,Category,Event,Address,Details\n";
        m_eventFile.flush();

        m_startTime = std::chrono::steady_clock::now();
        m_initialized = true;

        LOG_INFO("EventRecorder", "Event recording started: %s", fname.str().c_str());
        return true;
    }

    void RecordEvent(const std::string& category, const std::string& eventName,
                     const std::string& details = "", uintptr_t address = 0)
    {
        if (!m_initialized)
            return;

        GameEvent evt;
        evt.timestamp = GetTimestamp();
        evt.category = category;
        evt.eventName = eventName;
        evt.details = details;
        evt.address = address;
        evt.threadId = GetCurrentThreadId();
        evt.tickCount = GetTickCount64();

        {
            std::lock_guard<std::mutex> lock(m_mutex);

            // Track event counts
            std::string key = category + "." + eventName;
            m_eventCounts[key]++;

            // Write to CSV
            m_eventFile << EscapeCsv(evt.timestamp) << ","
                       << evt.tickCount << ","
                       << evt.threadId << ","
                       << EscapeCsv(evt.category) << ","
                       << EscapeCsv(evt.eventName) << ",";

            if (evt.address)
            {
                char addrBuf[32];
                snprintf(addrBuf, sizeof(addrBuf), "0x%llX", (unsigned long long)evt.address);
                m_eventFile << addrBuf;
            }

            m_eventFile << "," << EscapeCsv(evt.details) << "\n";

            m_totalEvents++;

            // Periodic flush every 50 events
            if (m_totalEvents % 50 == 0)
                m_eventFile.flush();
        }

        // Also log to main log at trace level
        LOG_TRACE("Event", "[%s] %s: %s", category.c_str(), eventName.c_str(), details.c_str());
    }

    void RecordPakEvent(const std::string& eventName, const std::string& pakPath,
                        const std::string& details = "")
    {
        RecordEvent("PAK", eventName, pakPath + " | " + details);
    }

    void RecordHookEvent(const std::string& hookName, uintptr_t address,
                         const std::string& result = "")
    {
        std::string details = "Hook: " + hookName;
        if (!result.empty())
            details += " Result: " + result;
        RecordEvent("HOOK", hookName, details, address);
    }

    void RecordBypassEvent(const std::string& checkType, bool bypassed,
                           const std::string& details = "")
    {
        std::string eventName = bypassed ? "BYPASSED" : "FAILED";
        RecordEvent("BYPASS", checkType + "_" + eventName, details);
    }

    void RecordProcessEvent(const std::string& className, const std::string& funcName,
                            uintptr_t objAddr = 0)
    {
        RecordEvent("UE4", "ProcessEvent",
                    className + "::" + funcName, objAddr);
    }

    void RecordFileAccess(const std::string& operation, const std::string& filePath,
                          bool success = true)
    {
        std::string details = filePath + " [" + (success ? "OK" : "FAIL") + "]";
        RecordEvent("FILE", operation, details);
    }

    void PrintSummary()
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto elapsed = std::chrono::steady_clock::now() - m_startTime;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

        LOG_INFO("EventRecorder", "=== Event Summary (%.1f minutes) ===", seconds / 60.0);
        LOG_INFO("EventRecorder", "Total events recorded: %zu", m_totalEvents);

        for (const auto& [key, count] : m_eventCounts)
        {
            LOG_INFO("EventRecorder", "  %s: %zu times", key.c_str(), count);
        }
    }

    void Shutdown()
    {
        PrintSummary();

        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_eventFile.is_open())
        {
            m_eventFile.flush();
            m_eventFile.close();
        }
        m_initialized = false;
    }

    size_t GetTotalEvents() const { return m_totalEvents; }

private:
    EventRecorder() = default;
    ~EventRecorder() { if (m_initialized) Shutdown(); }

    EventRecorder(const EventRecorder&) = delete;
    EventRecorder& operator=(const EventRecorder&) = delete;

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

    static std::string EscapeCsv(const std::string& str)
    {
        if (str.find_first_of(",\"\n\r") == std::string::npos)
            return str;

        std::string escaped = "\"";
        for (char c : str)
        {
            if (c == '"')
                escaped += "\"\"";
            else
                escaped += c;
        }
        escaped += "\"";
        return escaped;
    }

    std::mutex                                     m_mutex;
    std::ofstream                                  m_eventFile;
    bool                                           m_initialized = false;
    size_t                                         m_totalEvents = 0;
    std::unordered_map<std::string, size_t>        m_eventCounts;
    std::chrono::steady_clock::time_point          m_startTime;
};
