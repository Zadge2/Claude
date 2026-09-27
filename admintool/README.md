# admintool

A Windows system-administration CLI written in C++20 with no third-party dependencies
(Win32, NetAPI, Service Control Manager, and Windows Event Log APIs only).

## Build

**Visual Studio / MSVC** (Developer Command Prompt):

```
cmake -S . -B build
cmake --build build --config Release
```

**Cross-compile from Linux** (MinGW-w64):

```
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Requires Windows 10 / Server 2016 or newer.

## Usage

```
admintool [--json] [--no-truncate] <group> <action> [arguments]
```

`--json` switches every command to machine-readable output (arrays of objects, typed numbers/booleans;
`logs tail` emits one JSON object per line). Run `admintool help` for the full reference.

| Group   | Actions |
|---------|---------|
| `sys`   | `info`, `disks`, `procs [--filter T] [--sort mem\|cpu\|pid\|name] [--top N]`, `kill <pid> [--yes]` |
| `users` | `list`, `info <u>`, `add <u> [--password P] [--fullname N] [--comment C] [--admin]`, `del <u> [--yes]`, `enable\|disable\|unlock <u>`, `passwd <u>`, `groups`, `members <g>`, `join\|leave <u> <g>` |
| `svc`   | `list [--state running\|stopped] [--filter T]`, `status <s>`, `start <s>`, `stop <s> [--with-deps]`, `restart <s> [--with-deps]`, `startup <s> auto\|delayed\|manual\|disabled` |
| `logs`  | `channels [--filter T]`, `query [--channel C] [--level L] [--source P] [--id N] [--since 12h] [--count N] [--oldest-first] [--xpath Q]`, `tail [--channel C] [--level L] [--source P] [--id N]` |

### Examples

```
admintool sys info
admintool sys procs --sort cpu --top 10
admintool --json svc list --state running
admintool svc restart Spooler --with-deps
admintool users add alice --fullname "Alice Smith" --admin
admintool logs query --channel Application --level error --since 24h
admintool --json logs tail --channel System --level warning
```

## Notes

- Write operations (user management, service control, killing other users' processes, reading the
  Security log) need an elevated prompt. On access-denied errors the tool prints a hint when it is
  not elevated.
- Passwords are prompted without echo when `--password` is omitted (or read from a single line of
  redirected stdin) and wiped from memory after use. Prefer the prompt over `--password`, which is
  visible in the process command line.
- Destructive actions (`users del`, `sys kill`) ask for confirmation unless `--yes` is given.
- Exit codes: `0` success, `1` operation failed, `2` usage error.
