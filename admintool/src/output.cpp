#include "output.hpp"

#include <algorithm>
#include <cstdio>
#include <iostream>

namespace admin {

namespace {

bool g_json = false;
std::size_t g_max_cell = 60;

std::string to_text(const Value& v) {
    return std::visit(
        [](const auto& x) -> std::string {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, std::nullptr_t>) return "-";
            else if constexpr (std::is_same_v<T, bool>) return x ? "yes" : "no";
            else if constexpr (std::is_same_v<T, std::int64_t>) return std::to_string(x);
            else return x;
        },
        v);
}

std::string to_json(const Value& v) {
    return std::visit(
        [](const auto& x) -> std::string {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, std::nullptr_t>) return "null";
            else if constexpr (std::is_same_v<T, bool>) return x ? "true" : "false";
            else if constexpr (std::is_same_v<T, std::int64_t>) return std::to_string(x);
            else return "\"" + json_escape(x) + "\"";
        },
        v);
}

// Display width in code points (good enough for console alignment of most text).
std::size_t display_width(const std::string& s) {
    std::size_t n = 0;
    for (unsigned char c : s)
        if ((c & 0xC0) != 0x80) ++n;
    return n;
}

std::string truncate(std::string s) {
    // Collapse newlines/tabs so a single cell never breaks the table layout.
    for (auto& c : s)
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    if (g_max_cell == 0 || display_width(s) <= g_max_cell) return s;
    std::size_t cps = 0, i = 0;
    for (; i < s.size(); ++i) {
        if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) {
            if (cps == g_max_cell - 3) break;
            ++cps;
        }
    }
    return s.substr(0, i) + "...";
}

std::string json_object(const std::vector<std::string>& keys, const std::vector<Value>& vals) {
    std::string out = "{";
    for (std::size_t i = 0; i < keys.size() && i < vals.size(); ++i) {
        if (i) out += ",";
        out += "\"" + json_escape(keys[i]) + "\":" + to_json(vals[i]);
    }
    return out + "}";
}

}  // namespace

void set_json_output(bool enabled) { g_json = enabled; }
bool json_output() { return g_json; }
void set_max_cell_width(std::size_t width) { g_max_cell = width; }

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

void print_table(const Table& t) {
    if (g_json) {
        std::cout << "[";
        for (std::size_t r = 0; r < t.rows.size(); ++r) {
            std::cout << (r ? ",\n " : "\n ") << json_object(t.columns, t.rows[r]);
        }
        std::cout << (t.rows.empty() ? "]\n" : "\n]\n");
        return;
    }

    std::vector<std::vector<std::string>> cells;
    std::vector<std::size_t> widths;
    for (const auto& c : t.columns) widths.push_back(display_width(c));
    for (const auto& row : t.rows) {
        std::vector<std::string> line;
        for (std::size_t i = 0; i < t.columns.size(); ++i) {
            std::string s = i < row.size() ? truncate(to_text(row[i])) : "";
            widths[i] = std::max(widths[i], display_width(s));
            line.push_back(std::move(s));
        }
        cells.push_back(std::move(line));
    }

    auto emit = [&](const std::vector<std::string>& line) {
        std::string out;
        for (std::size_t i = 0; i < line.size(); ++i) {
            out += line[i];
            if (i + 1 < line.size()) out += std::string(widths[i] - display_width(line[i]) + 2, ' ');
        }
        std::cout << out << "\n";
    };

    emit(t.columns);
    std::vector<std::string> sep;
    for (auto w : widths) sep.emplace_back(w, '-');
    emit(sep);
    for (const auto& line : cells) emit(line);
    std::cout << "(" << t.rows.size() << " row" << (t.rows.size() == 1 ? "" : "s") << ")\n";
}

void print_record(const Record& r) {
    if (g_json) {
        std::vector<std::string> keys;
        std::vector<Value> vals;
        for (const auto& [k, v] : r) {
            keys.push_back(k);
            vals.push_back(v);
        }
        std::cout << json_object(keys, vals) << "\n";
        return;
    }
    std::size_t w = 0;
    for (const auto& [k, _] : r) w = std::max(w, display_width(k));
    for (const auto& [k, v] : r) {
        std::cout << k << std::string(w - display_width(k), ' ') << " : " << to_text(v) << "\n";
    }
}

void print_ok(const std::string& message) {
    if (g_json)
        std::cout << "{\"ok\":true,\"message\":\"" << json_escape(message) << "\"}\n";
    else
        std::cout << message << "\n";
}

void print_stream_record(const Record& r) {
    if (g_json) {
        std::vector<std::string> keys;
        std::vector<Value> vals;
        for (const auto& [k, v] : r) {
            keys.push_back(k);
            vals.push_back(v);
        }
        std::cout << json_object(keys, vals) << std::endl;
        return;
    }
    print_record(r);
    std::cout << std::endl;
}

}  // namespace admin
