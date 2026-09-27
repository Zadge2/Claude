// "sys" command group: system overview, disks, processes.

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdio>
#include <iostream>

#include "args.hpp"
#include "commands.hpp"
#include "output.hpp"
#include "util.hpp"

namespace admin {

namespace {

std::uint64_t ft_to_u64(const FILETIME& ft) {
    return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

std::string reg_string(HKEY root, const wchar_t* path, const wchar_t* name) {
    wchar_t buf[512];
    DWORD size = sizeof(buf);
    if (RegGetValueW(root, path, name, RRF_RT_REG_SZ, nullptr, buf, &size) != ERROR_SUCCESS) return "";
    return trim(to_utf8(buf));
}

std::string os_version_string() {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (HMODULE ntdll = GetModuleHandleW(L"ntdll.dll")) {
        auto fn = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));
        if (fn) fn(&vi);
    }

    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::string product = reg_string(HKEY_LOCAL_MACHINE, key, L"ProductName");
    std::string display = reg_string(HKEY_LOCAL_MACHINE, key, L"DisplayVersion");
    // Windows 11 still reports "Windows 10" in ProductName.
    if (vi.dwBuildNumber >= 22000 && product.rfind("Windows 10", 0) == 0) product.replace(8, 2, "11");

    std::string out = product.empty() ? "Windows" : product;
    if (!display.empty()) out += " " + display;
    out += " (build " + std::to_string(vi.dwMajorVersion) + "." + std::to_string(vi.dwMinorVersion) + "." +
           std::to_string(vi.dwBuildNumber) + ")";
    return out;
}

std::string arch_string(WORD arch) {
    switch (arch) {
        case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
        case PROCESSOR_ARCHITECTURE_ARM64: return "ARM64";
        case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
        case PROCESSOR_ARCHITECTURE_ARM: return "ARM";
        default: return "unknown";
    }
}

// Samples overall CPU utilisation over a short interval.
double cpu_usage_percent(DWORD sample_ms) {
    FILETIME idle1, kern1, user1, idle2, kern2, user2;
    if (!GetSystemTimes(&idle1, &kern1, &user1)) return -1;
    Sleep(sample_ms);
    if (!GetSystemTimes(&idle2, &kern2, &user2)) return -1;
    auto idle = ft_to_u64(idle2) - ft_to_u64(idle1);
    auto total = (ft_to_u64(kern2) - ft_to_u64(kern1)) + (ft_to_u64(user2) - ft_to_u64(user1));  // kernel includes idle
    if (total == 0) return 0;
    return 100.0 * static_cast<double>(total - idle) / static_cast<double>(total);
}

std::string percent(double v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%.1f%%", v);
    return buf;
}

int sys_info(const Args& a) {
    a.allow_only({});
    wchar_t host[256];
    DWORD host_len = 256;
    GetComputerNameExW(ComputerNameDnsFullyQualified, host, &host_len);

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);

    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    std::uint64_t uptime = GetTickCount64() / 1000;
    double cpu = cpu_usage_percent(500);

    Record r{
        {"hostname", str(to_utf8(host))},
        {"os", str(os_version_string())},
        {"architecture", str(arch_string(si.wProcessorArchitecture))},
        {"cpu_model", str(reg_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                                     L"ProcessorNameString"))},
        {"logical_cpus", num(si.dwNumberOfProcessors)},
    };
    if (json_output()) {
        r.push_back({"cpu_usage_percent", num(static_cast<std::int64_t>(cpu + 0.5))});
        r.push_back({"memory_total_bytes", num(static_cast<std::int64_t>(mem.ullTotalPhys))});
        r.push_back({"memory_available_bytes", num(static_cast<std::int64_t>(mem.ullAvailPhys))});
        r.push_back({"memory_load_percent", num(mem.dwMemoryLoad)});
        r.push_back({"uptime_seconds", num(static_cast<std::int64_t>(uptime))});
    } else {
        r.push_back({"cpu_usage", str(percent(cpu))});
        r.push_back({"memory", str(format_bytes(mem.ullTotalPhys - mem.ullAvailPhys) + " / " +
                                   format_bytes(mem.ullTotalPhys) + " (" + std::to_string(mem.dwMemoryLoad) + "%)")});
        r.push_back({"page_file", str(format_bytes(mem.ullTotalPageFile - mem.ullAvailPageFile) + " / " +
                                      format_bytes(mem.ullTotalPageFile))});
        r.push_back({"uptime", str(format_duration(uptime))});
    }
    r.push_back({"elevated", is_elevated()});
    print_record(r);
    return 0;
}

std::string drive_type_name(UINT t) {
    switch (t) {
        case DRIVE_FIXED: return "fixed";
        case DRIVE_REMOVABLE: return "removable";
        case DRIVE_REMOTE: return "network";
        case DRIVE_CDROM: return "cdrom";
        case DRIVE_RAMDISK: return "ramdisk";
        default: return "unknown";
    }
}

int sys_disks(const Args& a) {
    a.allow_only({});
    wchar_t buf[1024];
    DWORD len = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(buf)), buf);
    if (len == 0 || len > std::size(buf)) throw WinError("GetLogicalDriveStrings");

    Table t{{"drive", "type", "label", "fs", "size", "free", "used%"}, {}};
    // Don't pop "insert disk" dialogs for empty card readers / optical drives.
    UINT old_mode = SetErrorMode(SEM_FAILCRITICALERRORS);
    for (const wchar_t* p = buf; *p; p += wcslen(p) + 1) {
        UINT type = GetDriveTypeW(p);
        wchar_t label[MAX_PATH + 1] = L"", fs[MAX_PATH + 1] = L"";
        ULARGE_INTEGER avail{}, total{}, free{};
        bool ready = GetVolumeInformationW(p, label, MAX_PATH + 1, nullptr, nullptr, nullptr, fs, MAX_PATH + 1) &&
                     GetDiskFreeSpaceExW(p, &avail, &total, &free);
        std::vector<Value> row{str(to_utf8(p)), str(drive_type_name(type))};
        if (!ready) {
            row.insert(row.end(), {str("(not ready)"), nullptr, nullptr, nullptr, nullptr});
        } else {
            std::int64_t used_pct = total.QuadPart ? static_cast<std::int64_t>(
                                                         100 * (total.QuadPart - free.QuadPart) / total.QuadPart)
                                                   : 0;
            row.push_back(str(to_utf8(label)));
            row.push_back(str(to_utf8(fs)));
            if (json_output()) {
                row.push_back(num(static_cast<std::int64_t>(total.QuadPart)));
                row.push_back(num(static_cast<std::int64_t>(free.QuadPart)));
            } else {
                row.push_back(str(format_bytes(total.QuadPart)));
                row.push_back(str(format_bytes(free.QuadPart)));
            }
            row.push_back(num(used_pct));
        }
        t.rows.push_back(std::move(row));
    }
    SetErrorMode(old_mode);
    print_table(t);
    return 0;
}

struct ProcInfo {
    DWORD pid = 0;
    DWORD ppid = 0;
    DWORD threads = 0;
    std::string name;
    std::string user;
    std::uint64_t working_set = 0;
    std::uint64_t cpu_100ns = 0;
    bool accessible = false;
};

std::string process_user(HANDLE proc) {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &raw)) return "";
    UniqueHandle token(raw);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    if (size == 0) return "";
    std::vector<BYTE> buf(size);
    if (!GetTokenInformation(token.get(), TokenUser, buf.data(), size, &size)) return "";
    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    wchar_t name[256], domain[256];
    DWORD name_len = 256, domain_len = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, tu->User.Sid, name, &name_len, domain, &domain_len, &use)) return "";
    return to_utf8(domain) + "\\" + to_utf8(name);
}

std::vector<ProcInfo> snapshot_processes() {
    HANDLE raw = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (raw == INVALID_HANDLE_VALUE) throw WinError("CreateToolhelp32Snapshot");
    UniqueHandle snap(raw);

    std::vector<ProcInfo> out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32FirstW(snap.get(), &pe); ok; ok = Process32NextW(snap.get(), &pe)) {
        ProcInfo p;
        p.pid = pe.th32ProcessID;
        p.ppid = pe.th32ParentProcessID;
        p.threads = pe.cntThreads;
        p.name = to_utf8(pe.szExeFile);
        if (HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid)) {
            UniqueHandle proc(h);
            p.accessible = true;
            PROCESS_MEMORY_COUNTERS pmc{};
            if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) p.working_set = pmc.WorkingSetSize;
            FILETIME c, e, k, u;
            if (GetProcessTimes(h, &c, &e, &k, &u)) p.cpu_100ns = ft_to_u64(k) + ft_to_u64(u);
            p.user = process_user(h);
        }
        out.push_back(std::move(p));
    }
    return out;
}

int sys_procs(const Args& a) {
    a.allow_only({"filter", "sort", "top"});
    auto procs = snapshot_processes();

    if (auto f = a.get("filter")) {
        std::string needle = lower(*f);
        std::erase_if(procs, [&](const ProcInfo& p) {
            return lower(p.name).find(needle) == std::string::npos && std::to_string(p.pid) != *f;
        });
    }

    std::string sort = lower(a.get_or("sort", "mem"));
    if (sort == "mem")
        std::sort(procs.begin(), procs.end(), [](auto& x, auto& y) { return x.working_set > y.working_set; });
    else if (sort == "cpu")
        std::sort(procs.begin(), procs.end(), [](auto& x, auto& y) { return x.cpu_100ns > y.cpu_100ns; });
    else if (sort == "pid")
        std::sort(procs.begin(), procs.end(), [](auto& x, auto& y) { return x.pid < y.pid; });
    else if (sort == "name")
        std::sort(procs.begin(), procs.end(), [](auto& x, auto& y) { return lower(x.name) < lower(y.name); });
    else
        throw UsageError("--sort must be one of mem, cpu, pid, name");

    long long top = a.get_int("top", 0);
    if (top > 0 && static_cast<std::size_t>(top) < procs.size()) procs.resize(static_cast<std::size_t>(top));

    Table t{{"pid", "ppid", "name", "user", "threads", "memory", "cpu_time"}, {}};
    for (const auto& p : procs) {
        std::uint64_t cpu_sec = p.cpu_100ns / 10000000ULL;
        t.rows.push_back({
            num(p.pid),
            num(p.ppid),
            str(p.name),
            p.user.empty() ? Value{nullptr} : str(p.user),
            num(p.threads),
            !p.accessible ? Value{nullptr}
            : json_output() ? num(static_cast<std::int64_t>(p.working_set))
                            : str(format_bytes(p.working_set)),
            !p.accessible ? Value{nullptr}
            : json_output() ? num(static_cast<std::int64_t>(cpu_sec))
                            : str(format_duration(cpu_sec)),
        });
    }
    print_table(t);
    return 0;
}

int sys_kill(const Args& a) {
    a.allow_only({"yes"});
    const std::string& pid_str = a.require(1, "<pid>");
    DWORD pid = 0;
    try {
        pid = static_cast<DWORD>(std::stoul(pid_str));
    } catch (const std::exception&) {
        throw UsageError("invalid pid '" + pid_str + "'");
    }
    if (pid == 0 || pid == 4) throw UsageError("refusing to terminate a system process (pid " + pid_str + ")");
    if (pid == GetCurrentProcessId()) throw UsageError("refusing to terminate admintool itself");

    std::string name = "pid " + pid_str;
    for (const auto& p : snapshot_processes())
        if (p.pid == pid) name = p.name + " (pid " + pid_str + ")";

    if (!a.flag("yes") && !confirm("Terminate " + name + "?")) {
        std::cerr << "aborted\n";
        return 1;
    }

    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (!h) throw WinError("OpenProcess(" + pid_str + ")");
    UniqueHandle proc(h);
    if (!TerminateProcess(h, 1)) throw WinError("TerminateProcess(" + pid_str + ")");
    WaitForSingleObject(h, 5000);
    print_ok("Terminated " + name);
    return 0;
}

}  // namespace

int cmd_sys(const std::vector<std::string>& argv) {
    Args a(argv, {"filter", "sort", "top"});
    const std::string& action = a.require(0, "sys action (info, disks, procs, kill)");
    if (action == "info") return sys_info(a);
    if (action == "disks") return sys_disks(a);
    if (action == "procs" || action == "ps") return sys_procs(a);
    if (action == "kill") return sys_kill(a);
    throw UsageError("unknown sys action '" + action + "'");
}

}  // namespace admin
