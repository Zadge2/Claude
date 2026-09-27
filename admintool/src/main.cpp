// admintool - Windows system administration CLI.
//
//   admintool [--json] [--no-truncate] <group> <action> [arguments]
//
// Groups: sys, users, svc, logs. Run "admintool help" for details.

#include <windows.h>

#include <iostream>
#include <string>
#include <vector>

#include "commands.hpp"
#include "output.hpp"
#include "util.hpp"

namespace {

constexpr const char* kUsage = R"(admintool 1.0 - Windows administration tool

Usage: admintool [--json] [--no-truncate] <group> <action> [arguments]

Global options:
  --json          Emit machine-readable JSON instead of tables
  --no-truncate   Do not shorten long table cells

System (sys):
  sys info                              OS, CPU, memory, uptime overview
  sys disks                             Fixed/removable volumes and free space
  sys procs [--filter TEXT] [--sort mem|pid|name|cpu] [--top N]
                                        List processes (cpu = CPU time)
  sys kill <pid> [--yes]                Terminate a process

Users (users):
  users list                            Local user accounts
  users info <user>                     Account details and group membership
  users add <user> [--password P] [--fullname NAME] [--comment TEXT] [--admin]
                                        Create a local account (prompts for password)
  users del <user> [--yes]              Delete an account
  users enable|disable|unlock <user>    Change account state
  users passwd <user> [--password P]    Reset a password (prompts if omitted)
  users groups                          Local groups
  users members <group>                 Members of a local group
  users join|leave <user> <group>       Add/remove a user to/from a local group

Services (svc):
  svc list [--state running|stopped] [--filter TEXT]
  svc status <name>                     Detailed status and configuration
  svc start <name> [--timeout SEC]
  svc stop <name> [--timeout SEC] [--with-deps]
  svc restart <name> [--timeout SEC] [--with-deps]
  svc startup <name> auto|delayed|manual|disabled

Logs (logs):
  logs channels [--filter TEXT]         Available event log channels
  logs query [--channel NAME] [--level critical|error|warning|info|verbose]
             [--source PROVIDER] [--id N] [--since DURATION] [--count N]
             [--oldest-first] [--xpath QUERY]
                                        DURATION examples: 30m, 12h, 7d
  logs tail  [--channel NAME] [--level ...] [--source PROVIDER] [--id N]
                                        Stream new events until Ctrl+C

Most write operations require an elevated (Administrator) prompt.
)";

int usage(int code) {
    (code == 0 ? std::cout : std::cerr) << kUsage;
    return code;
}

}  // namespace

int wmain(int argc, wchar_t** wargv) {
    // All output is UTF-8; make the console render it correctly.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string a = admin::to_utf8(wargv[i]);
        if (a == "--json") admin::set_json_output(true);
        else if (a == "--no-truncate") admin::set_max_cell_width(0);
        else args.push_back(std::move(a));
    }

    if (args.empty()) return usage(1);
    const std::string group = args.front();
    if (group == "help" || group == "--help" || group == "-h" || group == "/?") return usage(0);
    if (group == "--version" || group == "version") {
        std::cout << "admintool 1.0.0\n";
        return 0;
    }

    std::vector<std::string> rest(args.begin() + 1, args.end());
    try {
        if (group == "sys") return admin::cmd_sys(rest);
        if (group == "users") return admin::cmd_users(rest);
        if (group == "svc") return admin::cmd_svc(rest);
        if (group == "logs") return admin::cmd_logs(rest);
        throw admin::UsageError("unknown command group '" + group + "'");
    } catch (const admin::UsageError& e) {
        std::cerr << "error: " << e.what() << "\nRun 'admintool help' for usage.\n";
        return 2;
    } catch (const admin::WinError& e) {
        std::cerr << "error: " << e.what() << "\n";
        if (e.code() == ERROR_ACCESS_DENIED && !admin::is_elevated())
            std::cerr << "hint: this operation likely requires an elevated (Run as administrator) prompt.\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
