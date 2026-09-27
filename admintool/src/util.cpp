#include "util.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iostream>

namespace admin {

std::string to_utf8(std::wstring_view ws) {
    if (ws.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string win_error_message(DWORD code) {
    LPWSTR buf = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);

    // NetAPI errors (2100-2999) live in netmsg.dll rather than the system table.
    if (len == 0 && code >= 2100 && code <= 2999) {
        HMODULE netmsg = LoadLibraryExW(L"netmsg.dll", nullptr, LOAD_LIBRARY_AS_DATAFILE);
        if (netmsg) {
            len = FormatMessageW(flags | FORMAT_MESSAGE_FROM_HMODULE, netmsg, code, 0,
                                 reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
            FreeLibrary(netmsg);
        }
    }

    std::string msg;
    if (len && buf) {
        msg = trim(to_utf8(std::wstring_view(buf, len)));
        LocalFree(buf);
    } else {
        msg = "Unknown error";
    }
    return msg + " (code " + std::to_string(code) + ")";
}

WinError::WinError(const std::string& context, DWORD code)
    : std::runtime_error(context + ": " + win_error_message(code)), code_(code) {}

bool is_elevated() {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) return false;
    UniqueHandle token(raw);
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    if (!GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &size)) return false;
    return elevation.TokenIsElevated != 0;
}

std::string format_bytes(std::uint64_t bytes) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 5) {
        v /= 1024.0;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
    return buf;
}

std::string format_duration(std::uint64_t seconds) {
    auto days = seconds / 86400;
    auto hours = (seconds % 86400) / 3600;
    auto mins = (seconds % 3600) / 60;
    auto secs = seconds % 60;
    char buf[64];
    if (days)
        std::snprintf(buf, sizeof(buf), "%llud %02lluh %02llum", static_cast<unsigned long long>(days),
                      static_cast<unsigned long long>(hours), static_cast<unsigned long long>(mins));
    else
        std::snprintf(buf, sizeof(buf), "%02llu:%02llu:%02llu", static_cast<unsigned long long>(hours),
                      static_cast<unsigned long long>(mins), static_cast<unsigned long long>(secs));
    return buf;
}

std::string format_filetime(const FILETIME& ft) {
    if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0) return "";
    SYSTEMTIME utc{}, local{};
    if (!FileTimeToSystemTime(&ft, &utc)) return "";
    if (!SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local)) local = utc;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u", local.wYear, local.wMonth, local.wDay,
                  local.wHour, local.wMinute, local.wSecond);
    return buf;
}

std::string format_unix_time(std::uint32_t t) {
    if (t == 0) return "never";
    // Seconds between 1601-01-01 and 1970-01-01, in 100ns units.
    ULONGLONG ticks = (static_cast<ULONGLONG>(t) + 11644473600ULL) * 10000000ULL;
    FILETIME ft{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
    return format_filetime(ft);
}

std::string trim(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::wstring read_password(const std::string& prompt) {
    std::cerr << prompt << std::flush;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool console = GetConsoleMode(in, &mode) != 0;
    if (console) SetConsoleMode(in, mode & ~ENABLE_ECHO_INPUT);

    std::wstring result;
    if (console) {
        wchar_t ch;
        DWORD read = 0;
        while (ReadConsoleW(in, &ch, 1, &read, nullptr) && read == 1) {
            if (ch == L'\r') continue;
            if (ch == L'\n') break;
            result.push_back(ch);
        }
        SetConsoleMode(in, mode);
    } else {
        // Redirected stdin (e.g. piped from a secret store): read one line.
        std::string line;
        std::getline(std::cin, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        result = to_wide(line);
        SecureZeroMemory(line.data(), line.size());
    }
    std::cerr << "\n";
    return result;
}

bool confirm(const std::string& question) {
    std::cerr << question << " [y/N] " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer)) return false;
    answer = lower(trim(answer));
    return answer == "y" || answer == "yes";
}

}  // namespace admin
