// "users" command group: local accounts and local groups via the NetAPI.

#include <windows.h>
#include <lm.h>

#include <iostream>

#include "args.hpp"
#include "commands.hpp"
#include "output.hpp"
#include "util.hpp"

namespace admin {

namespace {

using NetBuffer = std::unique_ptr<BYTE, FnDeleter<&NetApiBufferFree>>;

void check(NET_API_STATUS status, const std::string& context) {
    if (status != NERR_Success) throw WinError(context, status);
}

std::string safe(LPCWSTR s) { return s ? to_utf8(s) : std::string(); }

std::string priv_name(DWORD priv) {
    switch (priv) {
        case USER_PRIV_ADMIN: return "admin";
        case USER_PRIV_USER: return "user";
        case USER_PRIV_GUEST: return "guest";
        default: return "unknown";
    }
}

// Localised name of a builtin group (e.g. "Administrators" / "Administratoren").
std::wstring builtin_group_name(WELL_KNOWN_SID_TYPE type) {
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid);
    if (!CreateWellKnownSid(type, nullptr, sid, &sid_size)) throw WinError("CreateWellKnownSid");
    wchar_t name[256], domain[256];
    DWORD name_len = 256, domain_len = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, sid, name, &name_len, domain, &domain_len, &use))
        throw WinError("LookupAccountSid");
    return name;
}

std::wstring obtain_password(const Args& a, const std::string& user) {
    if (auto p = a.get("password")) return to_wide(*p);
    std::wstring first = read_password("New password for " + user + ": ");
    std::wstring second = read_password("Confirm password: ");
    bool match = first == second;
    SecureZeroMemory(second.data(), second.size() * sizeof(wchar_t));
    if (!match) {
        SecureZeroMemory(first.data(), first.size() * sizeof(wchar_t));
        throw UsageError("passwords do not match");
    }
    return first;
}

DWORD get_flags(const std::wstring& user) {
    LPBYTE raw = nullptr;
    check(NetUserGetInfo(nullptr, user.c_str(), 1, &raw), "NetUserGetInfo(" + to_utf8(user) + ")");
    NetBuffer buf(raw);
    return reinterpret_cast<USER_INFO_1*>(raw)->usri1_flags;
}

void set_flags(const std::wstring& user, DWORD flags) {
    USER_INFO_1008 info{flags};
    check(NetUserSetInfo(nullptr, user.c_str(), 1008, reinterpret_cast<LPBYTE>(&info), nullptr),
          "NetUserSetInfo(" + to_utf8(user) + ")");
}

std::string state_of(DWORD flags) {
    if (flags & UF_ACCOUNTDISABLE) return "disabled";
    if (flags & UF_LOCKOUT) return "locked";
    return "enabled";
}

int users_list(const Args& a) {
    a.allow_only({});
    Table t{{"name", "privilege", "state", "pwd_expires", "comment"}, {}};
    DWORD resume = 0;
    NET_API_STATUS status;
    do {
        LPBYTE raw = nullptr;
        DWORD read = 0, total = 0;
        status = NetUserEnum(nullptr, 1, FILTER_NORMAL_ACCOUNT, &raw, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) throw WinError("NetUserEnum", status);
        NetBuffer buf(raw);
        auto* users = reinterpret_cast<USER_INFO_1*>(raw);
        for (DWORD i = 0; i < read; ++i) {
            const auto& u = users[i];
            t.rows.push_back({str(safe(u.usri1_name)), str(priv_name(u.usri1_priv)), str(state_of(u.usri1_flags)),
                              !(u.usri1_flags & UF_DONT_EXPIRE_PASSWD), str(safe(u.usri1_comment))});
        }
    } while (status == ERROR_MORE_DATA);
    print_table(t);
    return 0;
}

int users_info(const Args& a) {
    a.allow_only({});
    std::wstring user = to_wide(a.require(1, "<user>"));
    LPBYTE raw = nullptr;
    check(NetUserGetInfo(nullptr, user.c_str(), 3, &raw), "NetUserGetInfo(" + to_utf8(user) + ")");
    NetBuffer buf(raw);
    auto* u = reinterpret_cast<USER_INFO_3*>(raw);

    std::string groups;
    LPBYTE graw = nullptr;
    DWORD read = 0, total = 0;
    if (NetUserGetLocalGroups(nullptr, user.c_str(), 0, LG_INCLUDE_INDIRECT, &graw, MAX_PREFERRED_LENGTH, &read,
                              &total) == NERR_Success) {
        NetBuffer gbuf(graw);
        auto* g = reinterpret_cast<LOCALGROUP_USERS_INFO_0*>(graw);
        for (DWORD i = 0; i < read; ++i) groups += (i ? ", " : "") + safe(g[i].lgrui0_name);
    }

    Record r{
        {"name", str(safe(u->usri3_name))},
        {"full_name", str(safe(u->usri3_full_name))},
        {"comment", str(safe(u->usri3_comment))},
        {"privilege", str(priv_name(u->usri3_priv))},
        {"state", str(state_of(u->usri3_flags))},
        {"password_required", !(u->usri3_flags & UF_PASSWD_NOTREQD)},
        {"password_can_change", !(u->usri3_flags & UF_PASSWD_CANT_CHANGE)},
        {"password_expires", !(u->usri3_flags & UF_DONT_EXPIRE_PASSWD)},
        {"password_expired", u->usri3_password_expired != 0},
        {"password_age", json_output() ? num(u->usri3_password_age) : str(format_duration(u->usri3_password_age))},
        {"last_logon", str(format_unix_time(u->usri3_last_logon))},
        {"logon_count", num(u->usri3_num_logons)},
        {"bad_password_count", num(u->usri3_bad_pw_count)},
        {"account_expires",
         str(u->usri3_acct_expires == TIMEQ_FOREVER ? "never" : format_unix_time(u->usri3_acct_expires))},
        {"home_dir", str(safe(u->usri3_home_dir))},
        {"local_groups", str(groups)},
    };
    print_record(r);
    return 0;
}

int users_add(const Args& a) {
    a.allow_only({"password", "fullname", "comment", "admin"});
    std::string name = a.require(1, "<user>");
    std::wstring wname = to_wide(name);
    std::wstring password = obtain_password(a, name);
    std::wstring comment = to_wide(a.get_or("comment", ""));

    USER_INFO_1 ui{};
    ui.usri1_name = wname.data();
    ui.usri1_password = password.data();
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_comment = comment.empty() ? nullptr : comment.data();
    ui.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT;

    DWORD parm_err = 0;
    NET_API_STATUS status = NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&ui), &parm_err);
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    check(status, "NetUserAdd(" + name + ")");

    if (auto full = a.get("fullname")) {
        std::wstring wfull = to_wide(*full);
        USER_INFO_1011 fi{wfull.data()};
        check(NetUserSetInfo(nullptr, wname.c_str(), 1011, reinterpret_cast<LPBYTE>(&fi), nullptr),
              "set full name");
    }

    std::string msg = "Created user " + name;
    if (a.flag("admin")) {
        std::wstring group = builtin_group_name(WinBuiltinAdministratorsSid);
        LOCALGROUP_MEMBERS_INFO_3 m{wname.data()};
        status = NetLocalGroupAddMembers(nullptr, group.c_str(), 3, reinterpret_cast<LPBYTE>(&m), 1);
        if (status != NERR_Success && status != ERROR_MEMBER_IN_ALIAS)
            throw WinError("user created, but adding to " + to_utf8(group) + " failed", status);
        msg += " (member of " + to_utf8(group) + ")";
    }
    print_ok(msg);
    return 0;
}

int users_del(const Args& a) {
    a.allow_only({"yes"});
    std::string name = a.require(1, "<user>");
    if (!a.flag("yes") && !confirm("Delete user account '" + name + "'? This cannot be undone.")) {
        std::cerr << "aborted\n";
        return 1;
    }
    check(NetUserDel(nullptr, to_wide(name).c_str()), "NetUserDel(" + name + ")");
    print_ok("Deleted user " + name);
    return 0;
}

int users_state(const Args& a, const std::string& action) {
    a.allow_only({});
    std::string name = a.require(1, "<user>");
    std::wstring wname = to_wide(name);
    DWORD flags = get_flags(wname);
    if (action == "enable") flags &= ~static_cast<DWORD>(UF_ACCOUNTDISABLE);
    else if (action == "disable") flags |= UF_ACCOUNTDISABLE;
    else flags &= ~static_cast<DWORD>(UF_LOCKOUT);  // unlock
    set_flags(wname, flags);
    print_ok("User " + name + ": " + (action == "unlock" ? std::string("unlocked") : action + "d"));
    return 0;
}

int users_passwd(const Args& a) {
    a.allow_only({"password"});
    std::string name = a.require(1, "<user>");
    std::wstring password = obtain_password(a, name);
    USER_INFO_1003 pi{password.data()};
    NET_API_STATUS status =
        NetUserSetInfo(nullptr, to_wide(name).c_str(), 1003, reinterpret_cast<LPBYTE>(&pi), nullptr);
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    check(status, "set password for " + name);
    print_ok("Password updated for " + name);
    return 0;
}

int users_groups(const Args& a) {
    a.allow_only({});
    Table t{{"group", "comment"}, {}};
    DWORD_PTR resume = 0;
    NET_API_STATUS status;
    do {
        LPBYTE raw = nullptr;
        DWORD read = 0, total = 0;
        status = NetLocalGroupEnum(nullptr, 1, &raw, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) throw WinError("NetLocalGroupEnum", status);
        NetBuffer buf(raw);
        auto* g = reinterpret_cast<LOCALGROUP_INFO_1*>(raw);
        for (DWORD i = 0; i < read; ++i) t.rows.push_back({str(safe(g[i].lgrpi1_name)), str(safe(g[i].lgrpi1_comment))});
    } while (status == ERROR_MORE_DATA);
    print_table(t);
    return 0;
}

std::string sid_usage_name(SID_NAME_USE u) {
    switch (u) {
        case SidTypeUser: return "user";
        case SidTypeGroup: return "group";
        case SidTypeWellKnownGroup: return "well-known group";
        case SidTypeAlias: return "alias";
        case SidTypeDeletedAccount: return "deleted";
        default: return "other";
    }
}

int users_members(const Args& a) {
    a.allow_only({});
    std::string group = a.require(1, "<group>");
    std::wstring wgroup = to_wide(group);
    Table t{{"member", "type"}, {}};
    DWORD_PTR resume = 0;
    NET_API_STATUS status;
    do {
        LPBYTE raw = nullptr;
        DWORD read = 0, total = 0;
        status = NetLocalGroupGetMembers(nullptr, wgroup.c_str(), 2, &raw, MAX_PREFERRED_LENGTH, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA)
            throw WinError("NetLocalGroupGetMembers(" + group + ")", status);
        NetBuffer buf(raw);
        auto* m = reinterpret_cast<LOCALGROUP_MEMBERS_INFO_2*>(raw);
        for (DWORD i = 0; i < read; ++i)
            t.rows.push_back({str(safe(m[i].lgrmi2_domainandname)), str(sid_usage_name(m[i].lgrmi2_sidusage))});
    } while (status == ERROR_MORE_DATA);
    print_table(t);
    return 0;
}

int users_membership(const Args& a, bool join) {
    a.allow_only({});
    std::string user = a.require(1, "<user>");
    std::string group = a.require(2, "<group>");
    std::wstring wuser = to_wide(user);
    LOCALGROUP_MEMBERS_INFO_3 m{wuser.data()};
    auto* data = reinterpret_cast<LPBYTE>(&m);
    NET_API_STATUS status = join ? NetLocalGroupAddMembers(nullptr, to_wide(group).c_str(), 3, data, 1)
                                 : NetLocalGroupDelMembers(nullptr, to_wide(group).c_str(), 3, data, 1);
    if (join && status == ERROR_MEMBER_IN_ALIAS) {
        print_ok(user + " is already a member of " + group);
        return 0;
    }
    if (!join && status == ERROR_MEMBER_NOT_IN_ALIAS) {
        print_ok(user + " is not a member of " + group);
        return 0;
    }
    check(status, std::string(join ? "add " : "remove ") + user + (join ? " to " : " from ") + group);
    print_ok(join ? "Added " + user + " to " + group : "Removed " + user + " from " + group);
    return 0;
}

}  // namespace

int cmd_users(const std::vector<std::string>& argv) {
    Args a(argv, {"password", "fullname", "comment"});
    const std::string& action = a.require(0, "users action");
    if (action == "list") return users_list(a);
    if (action == "info") return users_info(a);
    if (action == "add") return users_add(a);
    if (action == "del" || action == "delete") return users_del(a);
    if (action == "enable" || action == "disable" || action == "unlock") return users_state(a, action);
    if (action == "passwd") return users_passwd(a);
    if (action == "groups") return users_groups(a);
    if (action == "members") return users_members(a);
    if (action == "join") return users_membership(a, true);
    if (action == "leave") return users_membership(a, false);
    throw UsageError("unknown users action '" + action + "'");
}

}  // namespace admin
