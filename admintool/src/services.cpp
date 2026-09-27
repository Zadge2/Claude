// "svc" command group: Windows service control via the Service Control Manager.

#include <windows.h>

#include <chrono>
#include <iostream>
#include <type_traits>

#include "args.hpp"
#include "commands.hpp"
#include "output.hpp"
#include "util.hpp"

namespace admin {

namespace {

using UniqueSc = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, FnDeleter<&CloseServiceHandle>>;

UniqueSc open_scm(DWORD access) {
    SC_HANDLE h = OpenSCManagerW(nullptr, nullptr, access);
    if (!h) throw WinError("OpenSCManager");
    return UniqueSc(h);
}

UniqueSc open_service(SC_HANDLE scm, const std::string& name, DWORD access) {
    SC_HANDLE h = OpenServiceW(scm, to_wide(name).c_str(), access);
    if (!h) throw WinError("OpenService(" + name + ")");
    return UniqueSc(h);
}

std::string state_name(DWORD s) {
    switch (s) {
        case SERVICE_STOPPED: return "stopped";
        case SERVICE_START_PENDING: return "starting";
        case SERVICE_STOP_PENDING: return "stopping";
        case SERVICE_RUNNING: return "running";
        case SERVICE_CONTINUE_PENDING: return "resuming";
        case SERVICE_PAUSE_PENDING: return "pausing";
        case SERVICE_PAUSED: return "paused";
        default: return "unknown";
    }
}

std::string start_type_name(DWORD t, bool delayed) {
    switch (t) {
        case SERVICE_BOOT_START: return "boot";
        case SERVICE_SYSTEM_START: return "system";
        case SERVICE_AUTO_START: return delayed ? "delayed" : "auto";
        case SERVICE_DEMAND_START: return "manual";
        case SERVICE_DISABLED: return "disabled";
        default: return "unknown";
    }
}

// QueryServiceConfig / QueryServiceConfig2 use the "call twice" size protocol.
std::vector<BYTE> query_config(SC_HANDLE svc) {
    DWORD needed = 0;
    QueryServiceConfigW(svc, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return {};
    std::vector<BYTE> buf(needed);
    if (!QueryServiceConfigW(svc, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data()), needed, &needed)) return {};
    return buf;
}

std::vector<BYTE> query_config2(SC_HANDLE svc, DWORD level) {
    DWORD needed = 0;
    QueryServiceConfig2W(svc, level, nullptr, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return {};
    std::vector<BYTE> buf(needed);
    if (!QueryServiceConfig2W(svc, level, buf.data(), needed, &needed)) return {};
    return buf;
}

bool is_delayed(SC_HANDLE svc) {
    auto buf = query_config2(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO);
    return !buf.empty() && reinterpret_cast<SERVICE_DELAYED_AUTO_START_INFO*>(buf.data())->fDelayedAutostart;
}

SERVICE_STATUS_PROCESS query_status(SC_HANDLE svc, const std::string& name) {
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed))
        throw WinError("QueryServiceStatusEx(" + name + ")");
    return ssp;
}

// Polls until the service reaches `target`, honouring the service's wait hint.
void wait_for_state(SC_HANDLE svc, const std::string& name, DWORD target, std::chrono::seconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto st = query_status(svc, name);
        if (st.dwCurrentState == target) return;
        if (target == SERVICE_RUNNING && st.dwCurrentState == SERVICE_STOPPED) {
            DWORD code = st.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR ? st.dwServiceSpecificExitCode
                                                                             : st.dwWin32ExitCode;
            throw WinError("service " + name + " stopped during startup", code);
        }
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("timed out waiting for " + name + " to become " + state_name(target) +
                                     " (currently " + state_name(st.dwCurrentState) + ")");
        DWORD wait = st.dwWaitHint / 10;
        Sleep(wait < 250 ? 250 : wait > 2000 ? 2000 : wait);
    }
}

std::chrono::seconds timeout_of(const Args& a) {
    long long t = a.get_int("timeout", 30);
    if (t <= 0) throw UsageError("--timeout must be positive");
    return std::chrono::seconds(t);
}

int svc_list(const Args& a) {
    a.allow_only({"state", "filter"});
    std::string state_filter = lower(a.get_or("state", "all"));
    DWORD state = SERVICE_STATE_ALL;
    if (state_filter == "running") state = SERVICE_ACTIVE;
    else if (state_filter == "stopped") state = SERVICE_INACTIVE;
    else if (state_filter != "all") throw UsageError("--state must be running, stopped or all");
    std::string needle = lower(a.get_or("filter", ""));

    auto scm = open_scm(SC_MANAGER_ENUMERATE_SERVICE);
    std::vector<BYTE> buf;
    DWORD needed = 0, count = 0, resume = 0;
    Table t{{"name", "display_name", "state", "startup", "pid"}, {}};

    for (;;) {
        BOOL ok = EnumServicesStatusExW(scm.get(), SC_ENUM_PROCESS_INFO, SERVICE_WIN32, state, buf.data(),
                                        static_cast<DWORD>(buf.size()), &needed, &count, &resume, nullptr);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && err != ERROR_MORE_DATA) throw WinError("EnumServicesStatusEx", err);

        auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            std::string name = to_utf8(entries[i].lpServiceName);
            std::string display = to_utf8(entries[i].lpDisplayName);
            if (!needle.empty() && lower(name).find(needle) == std::string::npos &&
                lower(display).find(needle) == std::string::npos)
                continue;

            Value startup = nullptr;
            if (SC_HANDLE h = OpenServiceW(scm.get(), entries[i].lpServiceName, SERVICE_QUERY_CONFIG)) {
                UniqueSc svc(h);
                auto cfg = query_config(h);
                if (!cfg.empty())
                    startup = str(start_type_name(reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg.data())->dwStartType,
                                                  is_delayed(h)));
            }
            const auto& ssp = entries[i].ServiceStatusProcess;
            t.rows.push_back({str(name), str(display), str(state_name(ssp.dwCurrentState)), startup,
                              ssp.dwProcessId ? num(ssp.dwProcessId) : Value{nullptr}});
        }
        if (ok) break;
        // First call (or more data): grow the buffer and continue from `resume`.
        buf.resize(needed + buf.size());
        count = 0;
    }
    print_table(t);
    return 0;
}

int svc_status(const Args& a) {
    a.allow_only({});
    std::string name = a.require(1, "<service>");
    auto scm = open_scm(SC_MANAGER_CONNECT);
    auto svc = open_service(scm.get(), name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    auto st = query_status(svc.get(), name);
    auto cfg_buf = query_config(svc.get());
    if (cfg_buf.empty()) throw WinError("QueryServiceConfig(" + name + ")");
    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfg_buf.data());

    std::string description;
    auto desc_buf = query_config2(svc.get(), SERVICE_CONFIG_DESCRIPTION);
    if (!desc_buf.empty()) {
        auto* d = reinterpret_cast<SERVICE_DESCRIPTIONW*>(desc_buf.data());
        if (d->lpDescription) description = to_utf8(d->lpDescription);
    }

    std::string deps;
    for (const wchar_t* p = cfg->lpDependencies; p && *p; p += wcslen(p) + 1) {
        if (!deps.empty()) deps += ", ";
        // Group dependencies are prefixed with SC_GROUP_IDENTIFIER ('+').
        deps += to_utf8(p);
    }

    Record r{
        {"name", str(name)},
        {"display_name", str(to_utf8(cfg->lpDisplayName ? cfg->lpDisplayName : L""))},
        {"description", str(description)},
        {"state", str(state_name(st.dwCurrentState))},
        {"pid", st.dwProcessId ? num(st.dwProcessId) : Value{nullptr}},
        {"startup", str(start_type_name(cfg->dwStartType, is_delayed(svc.get())))},
        {"account", str(to_utf8(cfg->lpServiceStartName ? cfg->lpServiceStartName : L""))},
        {"binary", str(to_utf8(cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L""))},
        {"dependencies", str(deps)},
        {"shared_process", (st.dwServiceType & SERVICE_WIN32_SHARE_PROCESS) != 0},
        {"can_stop", (st.dwControlsAccepted & SERVICE_ACCEPT_STOP) != 0},
        {"exit_code", num(st.dwWin32ExitCode)},
    };
    print_record(r);
    return 0;
}

void start_service(SC_HANDLE scm, const std::string& name, std::chrono::seconds timeout) {
    auto svc = open_service(scm, name, SERVICE_START | SERVICE_QUERY_STATUS);
    auto st = query_status(svc.get(), name);
    if (st.dwCurrentState == SERVICE_RUNNING) return;
    if (!StartServiceW(svc.get(), 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) throw WinError("StartService(" + name + ")", err);
    }
    wait_for_state(svc.get(), name, SERVICE_RUNNING, timeout);
}

void stop_one(SC_HANDLE scm, const std::string& name, std::chrono::seconds timeout) {
    auto svc = open_service(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    auto st = query_status(svc.get(), name);
    if (st.dwCurrentState == SERVICE_STOPPED) return;
    if (st.dwCurrentState != SERVICE_STOP_PENDING) {
        SERVICE_STATUS ss{};
        if (!ControlService(svc.get(), SERVICE_CONTROL_STOP, &ss)) throw WinError("ControlService(stop " + name + ")");
    }
    wait_for_state(svc.get(), name, SERVICE_STOPPED, timeout);
}

// Returns active dependents in the order they must be stopped.
std::vector<std::string> active_dependents(SC_HANDLE scm, const std::string& name) {
    auto svc = open_service(scm, name, SERVICE_ENUMERATE_DEPENDENTS);
    DWORD needed = 0, count = 0;
    if (EnumDependentServicesW(svc.get(), SERVICE_ACTIVE, nullptr, 0, &needed, &count)) return {};
    if (GetLastError() != ERROR_MORE_DATA) throw WinError("EnumDependentServices(" + name + ")");
    std::vector<BYTE> buf(needed);
    auto* deps = reinterpret_cast<ENUM_SERVICE_STATUSW*>(buf.data());
    if (!EnumDependentServicesW(svc.get(), SERVICE_ACTIVE, deps, needed, &needed, &count))
        throw WinError("EnumDependentServices(" + name + ")");
    std::vector<std::string> out;
    for (DWORD i = 0; i < count; ++i) out.push_back(to_utf8(deps[i].lpServiceName));
    return out;
}

std::vector<std::string> stop_service(SC_HANDLE scm, const std::string& name, bool with_deps,
                                      std::chrono::seconds timeout) {
    auto deps = active_dependents(scm, name);
    if (!deps.empty() && !with_deps) {
        std::string list;
        for (const auto& d : deps) list += (list.empty() ? "" : ", ") + d;
        throw UsageError("service " + name + " has running dependents (" + list +
                         "); pass --with-deps to stop them too");
    }
    for (const auto& d : deps) stop_one(scm, d, timeout);
    stop_one(scm, name, timeout);
    return deps;
}

int svc_start(const Args& a) {
    a.allow_only({"timeout"});
    std::string name = a.require(1, "<service>");
    auto scm = open_scm(SC_MANAGER_CONNECT);
    start_service(scm.get(), name, timeout_of(a));
    print_ok("Service " + name + " is running");
    return 0;
}

int svc_stop(const Args& a) {
    a.allow_only({"timeout", "with-deps"});
    std::string name = a.require(1, "<service>");
    auto scm = open_scm(SC_MANAGER_CONNECT);
    auto deps = stop_service(scm.get(), name, a.flag("with-deps"), timeout_of(a));
    std::string msg = "Service " + name + " stopped";
    if (!deps.empty()) msg += " (" + std::to_string(deps.size()) + " dependent service(s) also stopped)";
    print_ok(msg);
    return 0;
}

int svc_restart(const Args& a) {
    a.allow_only({"timeout", "with-deps"});
    std::string name = a.require(1, "<service>");
    auto timeout = timeout_of(a);
    auto scm = open_scm(SC_MANAGER_CONNECT);
    auto deps = stop_service(scm.get(), name, a.flag("with-deps"), timeout);
    start_service(scm.get(), name, timeout);
    // Bring dependents back in reverse stop order.
    for (auto it = deps.rbegin(); it != deps.rend(); ++it) start_service(scm.get(), *it, timeout);
    print_ok("Service " + name + " restarted");
    return 0;
}

int svc_startup(const Args& a) {
    a.allow_only({});
    std::string name = a.require(1, "<service>");
    std::string mode = lower(a.require(2, "startup mode (auto|delayed|manual|disabled)"));
    DWORD type;
    if (mode == "auto" || mode == "delayed") type = SERVICE_AUTO_START;
    else if (mode == "manual") type = SERVICE_DEMAND_START;
    else if (mode == "disabled") type = SERVICE_DISABLED;
    else throw UsageError("startup mode must be auto, delayed, manual or disabled");

    auto scm = open_scm(SC_MANAGER_CONNECT);
    auto svc = open_service(scm.get(), name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    if (!ChangeServiceConfigW(svc.get(), SERVICE_NO_CHANGE, type, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr,
                              nullptr, nullptr, nullptr, nullptr))
        throw WinError("ChangeServiceConfig(" + name + ")");
    if (type == SERVICE_AUTO_START) {
        SERVICE_DELAYED_AUTO_START_INFO info{mode == "delayed"};
        if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info))
            throw WinError("ChangeServiceConfig2(" + name + ")");
    }
    print_ok("Service " + name + " startup set to " + mode);
    return 0;
}

}  // namespace

int cmd_svc(const std::vector<std::string>& argv) {
    Args a(argv, {"state", "filter", "timeout"});
    const std::string& action = a.require(0, "svc action");
    if (action == "list") return svc_list(a);
    if (action == "status") return svc_status(a);
    if (action == "start") return svc_start(a);
    if (action == "stop") return svc_stop(a);
    if (action == "restart") return svc_restart(a);
    if (action == "startup") return svc_startup(a);
    throw UsageError("unknown svc action '" + action + "'");
}

}  // namespace admin
