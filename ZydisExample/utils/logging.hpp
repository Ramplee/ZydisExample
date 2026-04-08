#pragma once

#include <cstdarg>
#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#include <Windows.h>
#endif

namespace Logging {

inline bool& UseAnsiColors() {
    static bool Enabled = true;
    return Enabled;
}

inline void InitializeConsole() {
    static bool Initialized = false;
    if (Initialized) {
        return;
    }
    Initialized = true;

#if defined(_WIN32)
    void* StdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (StdOutHandle == nullptr || StdOutHandle == INVALID_HANDLE_VALUE) {
        UseAnsiColors() = false;
        return;
    }

    DWORD Mode = 0;
    if (!GetConsoleMode(StdOutHandle, &Mode)) {
        UseAnsiColors() = false;
        return;
    }

    Mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(StdOutHandle, Mode)) {
        UseAnsiColors() = false;
        return;
    }
#endif
}

inline const char* BaseFileName(const char* Path) {
    const char* Forward = std::strrchr(Path, '/');
    const char* Back = std::strrchr(Path, '\\');
    const char* Pick = Forward && (!Back || Forward > Back) ? Forward : Back;
    return Pick ? Pick + 1 : Path;
}

inline void PrintColoredLine(const char* ColorCode, const char* LevelTag, const char* File, int Line,
                             const char* Fmt, std::va_list Args) {
    InitializeConsole();

    if (UseAnsiColors()) {
        std::printf("%s[%s] [%s:%d] ", ColorCode, LevelTag, BaseFileName(File), Line);
    } else {
        std::printf("[%s] [%s:%d] ", LevelTag, BaseFileName(File), Line);
    }
    std::vprintf(Fmt, Args);
    if (UseAnsiColors()) {
        std::printf("\033[0m\n");
    } else {
        std::printf("\n");
    }
}

inline void LogInfoV(const char* File, int Line, const char* Fmt, std::va_list Args) {
    PrintColoredLine("\033[34m", "INFO", File, Line, Fmt, Args);
}

inline void LogWarnV(const char* File, int Line, const char* Fmt, std::va_list Args) {
    PrintColoredLine("\033[33m", "WARN", File, Line, Fmt, Args);
}

inline void LogErrorV(const char* File, int Line, const char* Fmt, std::va_list Args) {
    PrintColoredLine("\033[31m", "ERROR", File, Line, Fmt, Args);
}

inline void LogInfo(const char* File, int Line, const char* Fmt, ...) {
    std::va_list Args;
    va_start(Args, Fmt);
    LogInfoV(File, Line, Fmt, Args);
    va_end(Args);
}

inline void LogWarn(const char* File, int Line, const char* Fmt, ...) {
    std::va_list Args;
    va_start(Args, Fmt);
    LogWarnV(File, Line, Fmt, Args);
    va_end(Args);
}

inline void LogError(const char* File, int Line, const char* Fmt, ...) {
    std::va_list Args;
    va_start(Args, Fmt);
    LogErrorV(File, Line, Fmt, Args);
    va_end(Args);
}

} // namespace Logging

#define LogInfo(Fmt, ...)  Logging::LogInfo(__FILE__, __LINE__, Fmt, ##__VA_ARGS__)
#define LogWarn(Fmt, ...)  Logging::LogWarn(__FILE__, __LINE__, Fmt, ##__VA_ARGS__)
#define LogError(Fmt, ...) Logging::LogError(__FILE__, __LINE__, Fmt, ##__VA_ARGS__)
