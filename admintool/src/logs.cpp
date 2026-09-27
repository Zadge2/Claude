// "logs" command group: Windows Event Log access via wevtapi.

#include <windows.h>
#include <winevt.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <iostream>
#include <map>
#include <type_traits>

#include "args.hpp"
#include "commands.hpp"
#include "output.hpp"
#include "util.hpp"

namespace admin {

namespace {

using UniqueEvt = std::unique_ptr<std::remove_pointer_t<EVT_HANDLE>, FnDeleter<&EvtClose>>;

const std::set<std::string> kFilterOptions = {"channel", "level", "source", "id", "since", "xpath"};

std::string level_name(unsigned level) {
    switch (level) {
        case 1: return "Critical";
        case 2: return "Error";
        case 3: return "Warning";
        case 0:  // LogAlways - used by e.g. the Security log for audit events
        case 4: return "Information";
        case 5: return "Verbose";
        default: return "Level " + std::to_string(level);
    }
}

// Parses "90s", "30m", "12h", "7d" (bare number = hours) into milliseconds.
std::uint64_t parse_duration_ms(const std::string& s) {
    if (s.empty()) throw UsageError("empty --since value");
    char unit = static_cast<char>(std::tolower(static_cast<unsigned char>(s.back())));
    std::string digits = std::isdigit(static_cast<unsigned char>(unit)) ? s : s.substr(0, s.size() - 1);
    if (std::isdigit(static_cast<unsigned char>(unit))) unit = 'h';
    std::uint64_t n = 0;
    try {
        std::size_t used = 0;
        n = std::stoull(digits, &used);
        if (used != digits.size()) throw std::invalid_argument("trailing");
    } catch (const std::exception&) {
        throw UsageError("invalid --since value '" + s + "' (examples: 30m, 12h, 7d)");
    }
    switch (unit) {
        case 's': return n * 1000;
        case 'm': return n * 60 * 1000;
        case 'h': return n * 3600 * 1000;
        case 'd': return n * 86400 * 1000;
        default: throw UsageError("invalid --since unit in '" + s + "' (use s, m, h or d)");
    }
}

// XPath string literal; event log XPath has no escape syntax, so pick a quote the value lacks.
std::string xpath_literal(const std::string& v) {
    if (v.find('\'') == std::string::npos) return "'" + v + "'";
    if (v.find('"') == std::string::npos) return "\"" + v + "\"";
    throw UsageError("value cannot contain both ' and \" characters: " + v);
}

std::string build_xpath(const Args& a) {
    if (auto x = a.get("xpath")) return *x;

    std::vector<std::string> conds;
    std::string level = lower(a.get_or("level", "verbose"));
    if (level == "critical") conds.push_back("Level=1");
    else if (level == "error") conds.push_back("(Level=1 or Level=2)");
    else if (level == "warning") conds.push_back("(Level=1 or Level=2 or Level=3)");
    else if (level == "info" || level == "information") conds.push_back("Level<=4");
    else if (level != "verbose" && level != "all")
        throw UsageError("--level must be critical, error, warning, info or verbose");

    if (auto src = a.get("source")) conds.push_back("Provider[@Name=" + xpath_literal(*src) + "]");
    if (a.get("id")) conds.push_back("EventID=" + std::to_string(a.get_int("id", 0)));
    if (auto since = a.get("since"))
        conds.push_back("TimeCreated[timediff(@SystemTime) <= " + std::to_string(parse_duration_ms(*since)) + "]");

    if (conds.empty()) return "*";
    std::string joined;
    for (const auto& c : conds) joined += (joined.empty() ? "" : " and ") + c;
    return "*[System[" + joined + "]]";
}

// Renders system properties and formats messages; caches publisher metadata handles.
class EventFormatter {
public:
    EventFormatter() : ctx_(EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem)) {
        if (!ctx_) throw WinError("EvtCreateRenderContext");
    }

    Record format(EVT_HANDLE event) {
        DWORD used = 0, props = 0;
        EvtRender(ctx_.get(), event, EvtRenderEventValues, 0, nullptr, &used, &props);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) throw WinError("EvtRender");
        std::vector<BYTE> buf(used);
        if (!EvtRender(ctx_.get(), event, EvtRenderEventValues, used, buf.data(), &used, &props))
            throw WinError("EvtRender");
        auto* v = reinterpret_cast<PEVT_VARIANT>(buf.data());

        auto string_at = [&](int idx) -> std::string {
            return v[idx].Type == EvtVarTypeString && v[idx].StringVal ? to_utf8(v[idx].StringVal) : "";
        };

        std::string provider = string_at(EvtSystemProviderName);
        std::int64_t id = v[EvtSystemEventID].Type == EvtVarTypeNull ? 0 : v[EvtSystemEventID].UInt16Val;
        unsigned level = v[EvtSystemLevel].Type == EvtVarTypeNull ? 4 : v[EvtSystemLevel].ByteVal;
        std::string time;
        if (v[EvtSystemTimeCreated].Type == EvtVarTypeFileTime) {
            ULONGLONG t = v[EvtSystemTimeCreated].FileTimeVal;
            FILETIME ft{static_cast<DWORD>(t), static_cast<DWORD>(t >> 32)};
            time = format_filetime(ft);
        }
        std::int64_t record_id = v[EvtSystemEventRecordId].Type == EvtVarTypeNull
                                     ? 0
                                     : static_cast<std::int64_t>(v[EvtSystemEventRecordId].UInt64Val);

        return Record{
            {"time", str(time)},
            {"level", str(level_name(level))},
            {"source", str(provider)},
            {"event_id", num(id)},
            {"record_id", num(record_id)},
            {"channel", str(string_at(EvtSystemChannel))},
            {"computer", str(string_at(EvtSystemComputer))},
            {"message", str(message(event, provider))},
        };
    }

private:
    std::string message(EVT_HANDLE event, const std::string& provider) {
        EVT_HANDLE pub = publisher(provider);
        if (!pub) return "(message unavailable: no publisher metadata)";
        DWORD used = 0;
        if (!EvtFormatMessage(pub, event, 0, 0, nullptr, EvtFormatMessageEvent, 0, nullptr, &used)) {
            DWORD err = GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) return "(message unavailable: " + win_error_message(err) + ")";
        }
        std::wstring buf(used, L'\0');
        if (!EvtFormatMessage(pub, event, 0, 0, nullptr, EvtFormatMessageEvent, used, buf.data(), &used)) {
            // Partial formatting (missing insert strings) still returns useful text.
            DWORD err = GetLastError();
            if (err != ERROR_EVT_UNRESOLVED_VALUE_INSERT && err != ERROR_EVT_UNRESOLVED_PARAMETER_INSERT &&
                err != ERROR_EVT_MAX_INSERTS_REACHED)
                return "(message unavailable: " + win_error_message(err) + ")";
        }
        buf.resize(wcsnlen(buf.c_str(), buf.size()));
        return trim(to_utf8(buf));
    }

    EVT_HANDLE publisher(const std::string& provider) {
        if (provider.empty()) return nullptr;
        auto it = publishers_.find(provider);
        if (it != publishers_.end()) return it->second.get();
        EVT_HANDLE h = EvtOpenPublisherMetadata(nullptr, to_wide(provider).c_str(), nullptr, 0, 0);
        return publishers_.emplace(provider, UniqueEvt(h)).first->second.get();
    }

    UniqueEvt ctx_;
    std::map<std::string, UniqueEvt> publishers_;
};

Table events_table() {
    return Table{{"time", "level", "source", "event_id", "record_id", "channel", "computer", "message"}, {}};
}

void add_row(Table& t, Record r) {
    std::vector<Value> row;
    for (auto& [_, v] : r) row.push_back(std::move(v));
    t.rows.push_back(std::move(row));
}

// Table mode hides verbose columns for readability.
void print_events(Table t) {
    if (!json_output()) {
        Table compact{{"time", "level", "source", "event_id", "message"}, {}};
        for (auto& r : t.rows) compact.rows.push_back({r[0], r[1], r[2], r[3], r[7]});
        print_table(compact);
    } else {
        print_table(t);
    }
}

int logs_channels(const Args& a) {
    a.allow_only({"filter"});
    std::string needle = lower(a.get_or("filter", ""));
    UniqueEvt en(EvtOpenChannelEnum(nullptr, 0));
    if (!en) throw WinError("EvtOpenChannelEnum");
    Table t{{"channel"}, {}};
    std::wstring buf(256, L'\0');
    for (;;) {
        DWORD used = 0;
        if (!EvtNextChannelPath(en.get(), static_cast<DWORD>(buf.size()), buf.data(), &used)) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) break;
            if (err == ERROR_INSUFFICIENT_BUFFER) {
                buf.resize(used);
                continue;
            }
            throw WinError("EvtNextChannelPath", err);
        }
        std::string name = to_utf8(buf.c_str());
        if (needle.empty() || lower(name).find(needle) != std::string::npos) t.rows.push_back({str(name)});
    }
    print_table(t);
    return 0;
}

int logs_query(const Args& a) {
    auto allowed = kFilterOptions;
    allowed.insert({"count", "oldest-first"});
    a.allow_only(allowed);

    std::wstring channel = to_wide(a.get_or("channel", "System"));
    std::wstring xpath = to_wide(build_xpath(a));
    long long count = a.get_int("count", 50);
    if (count <= 0) throw UsageError("--count must be positive");

    DWORD flags = EvtQueryChannelPath | (a.flag("oldest-first") ? EvtQueryForwardDirection : EvtQueryReverseDirection);
    UniqueEvt query(EvtQuery(nullptr, channel.c_str(), xpath.c_str(), flags));
    if (!query) throw WinError("EvtQuery(" + to_utf8(channel) + ")");

    EventFormatter fmt;
    Table t = events_table();
    EVT_HANDLE batch[64];
    while (t.rows.size() < static_cast<std::size_t>(count)) {
        DWORD want = static_cast<DWORD>(std::min<long long>(64, count - static_cast<long long>(t.rows.size())));
        DWORD got = 0;
        if (!EvtNext(query.get(), want, batch, INFINITE, 0, &got)) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) break;
            throw WinError("EvtNext", err);
        }
        for (DWORD i = 0; i < got; ++i) {
            UniqueEvt ev(batch[i]);
            add_row(t, fmt.format(ev.get()));
        }
    }
    print_events(std::move(t));
    return 0;
}

// ---- tail -----------------------------------------------------------------

HANDLE g_stop_event = nullptr;

BOOL WINAPI on_ctrl(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        SetEvent(g_stop_event);
        return TRUE;
    }
    return FALSE;
}

struct TailContext {
    EventFormatter fmt;
    std::atomic<bool> failed{false};
};

DWORD WINAPI on_event(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID user, EVT_HANDLE event) {
    auto* ctx = static_cast<TailContext*>(user);
    if (action == EvtSubscribeActionError) {
        std::cerr << "error: subscription failed: "
                  << win_error_message(static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(event))) << "\n";
        ctx->failed = true;
        SetEvent(g_stop_event);
        return 0;
    }
    try {
        print_stream_record(ctx->fmt.format(event));
    } catch (const std::exception& e) {
        std::cerr << "warning: " << e.what() << "\n";
    }
    return 0;
}

int logs_tail(const Args& a) {
    a.allow_only(kFilterOptions);
    if (a.get("since")) throw UsageError("--since is not supported by tail; use 'logs query'");

    std::wstring channel = to_wide(a.get_or("channel", "System"));
    std::wstring xpath = to_wide(build_xpath(a));

    UniqueHandle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stop) throw WinError("CreateEvent");
    g_stop_event = stop.get();
    SetConsoleCtrlHandler(on_ctrl, TRUE);

    TailContext ctx;
    // Callback-mode subscription: wevtapi invokes on_event on a worker thread (serially).
    UniqueEvt sub(EvtSubscribe(nullptr, nullptr, channel.c_str(), xpath.c_str(), nullptr, &ctx, on_event,
                               EvtSubscribeToFutureEvents));
    if (!sub) {
        SetConsoleCtrlHandler(on_ctrl, FALSE);
        throw WinError("EvtSubscribe(" + to_utf8(channel) + ")");
    }
    if (!json_output()) std::cerr << "Watching " << to_utf8(channel) << " (Ctrl+C to stop)...\n\n";

    WaitForSingleObject(stop.get(), INFINITE);
    sub.reset();  // blocks until any in-flight callback completes
    SetConsoleCtrlHandler(on_ctrl, FALSE);
    g_stop_event = nullptr;
    return ctx.failed ? 1 : 0;
}

}  // namespace

int cmd_logs(const std::vector<std::string>& argv) {
    Args a(argv, {"channel", "level", "source", "id", "since", "count", "xpath", "filter"});
    const std::string& action = a.require(0, "logs action");
    if (action == "channels") return logs_channels(a);
    if (action == "query") return logs_query(a);
    if (action == "tail") return logs_tail(a);
    throw UsageError("unknown logs action '" + action + "'");
}

}  // namespace admin
