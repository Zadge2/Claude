#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace admin {

// A cell/field value. Rendered as text in table mode, typed in JSON mode.
using Value = std::variant<std::nullptr_t, bool, std::int64_t, std::string>;

inline Value num(std::int64_t v) { return Value{v}; }
inline Value str(std::string v) { return Value{std::move(v)}; }

struct Table {
    std::vector<std::string> columns;
    std::vector<std::vector<Value>> rows;
};

using Record = std::vector<std::pair<std::string, Value>>;

void set_json_output(bool enabled);
bool json_output();

// Table mode truncates cells wider than this (0 = no limit). JSON is never truncated.
void set_max_cell_width(std::size_t width);

void print_table(const Table& t);          // JSON: array of objects
void print_record(const Record& r);        // JSON: single object
void print_ok(const std::string& message); // JSON: {"ok":true,"message":...}

// Streams one record as a single JSON line (NDJSON) or a "key: value" block; used by `logs tail`.
void print_stream_record(const Record& r);

std::string json_escape(const std::string& s);

}  // namespace admin
