#pragma once

#include <windows.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace admin {

// ---- RAII wrappers for Win32 handle types ---------------------------------

template <auto Fn>
struct FnDeleter {
    template <class T>
    void operator()(T* p) const noexcept {
        if (p) Fn(p);
    }
};

using UniqueHandle = std::unique_ptr<void, FnDeleter<&CloseHandle>>;

// ---- String conversion ----------------------------------------------------

std::string to_utf8(std::wstring_view ws);
std::wstring to_wide(std::string_view s);

// ---- Errors ---------------------------------------------------------------

std::string win_error_message(DWORD code);

class WinError : public std::runtime_error {
public:
    explicit WinError(const std::string& context, DWORD code = GetLastError());
    DWORD code() const noexcept { return code_; }

private:
    DWORD code_;
};

// Thrown for bad command-line usage; main() prints usage hints for these.
class UsageError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// ---- Misc helpers ---------------------------------------------------------

bool is_elevated();
std::string format_bytes(std::uint64_t bytes);
std::string format_duration(std::uint64_t seconds);
std::string format_filetime(const FILETIME& ft);   // local time, "YYYY-MM-DD HH:MM:SS"
std::string format_unix_time(std::uint32_t t);      // seconds since 1970 (NetAPI style)
std::string trim(std::string s);
std::string lower(std::string s);

// Reads a line from the console with echo disabled. Caller should wipe the result.
std::wstring read_password(const std::string& prompt);

// Asks a yes/no question on the console; returns true on 'y'/'yes'.
bool confirm(const std::string& question);

}  // namespace admin
