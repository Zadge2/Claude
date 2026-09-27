#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace admin {

// Minimal argument parser.
//   - "--name=value" and "--name value" set an option (the latter only for names in `value_options`).
//   - "--flag" sets a boolean flag.
//   - "--" ends option parsing; everything else is positional.
class Args {
public:
    Args(std::vector<std::string> argv, const std::set<std::string>& value_options);

    const std::vector<std::string>& positional() const { return positional_; }
    std::size_t count() const { return positional_.size(); }

    // Positional argument at index; throws UsageError with `what` if missing.
    const std::string& require(std::size_t index, const std::string& what) const;

    bool flag(const std::string& name) const { return flags_.count(name) != 0; }
    std::optional<std::string> get(const std::string& name) const;
    std::string get_or(const std::string& name, const std::string& fallback) const;
    long long get_int(const std::string& name, long long fallback) const;

    // Throws UsageError if any option/flag outside `known` was supplied.
    void allow_only(const std::set<std::string>& known) const;

private:
    std::vector<std::string> positional_;
    std::map<std::string, std::string> options_;
    std::set<std::string> flags_;
};

}  // namespace admin
