#include "args.hpp"

#include "util.hpp"

namespace admin {

Args::Args(std::vector<std::string> argv, const std::set<std::string>& value_options) {
    bool options_done = false;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        const std::string& a = argv[i];
        if (options_done || a.size() < 3 || a.rfind("--", 0) != 0) {
            if (a == "--") {
                options_done = true;
                continue;
            }
            positional_.push_back(a);
            continue;
        }
        std::string body = a.substr(2);
        auto eq = body.find('=');
        if (eq != std::string::npos) {
            options_[body.substr(0, eq)] = body.substr(eq + 1);
        } else if (value_options.count(body)) {
            if (i + 1 >= argv.size()) throw UsageError("option --" + body + " requires a value");
            options_[body] = argv[++i];
        } else {
            flags_.insert(body);
        }
    }
}

const std::string& Args::require(std::size_t index, const std::string& what) const {
    if (index >= positional_.size()) throw UsageError("missing argument: " + what);
    return positional_[index];
}

std::optional<std::string> Args::get(const std::string& name) const {
    auto it = options_.find(name);
    if (it == options_.end()) return std::nullopt;
    return it->second;
}

std::string Args::get_or(const std::string& name, const std::string& fallback) const {
    return get(name).value_or(fallback);
}

long long Args::get_int(const std::string& name, long long fallback) const {
    auto v = get(name);
    if (!v) return fallback;
    try {
        std::size_t used = 0;
        long long n = std::stoll(*v, &used);
        if (used != v->size()) throw std::invalid_argument("trailing");
        return n;
    } catch (const std::exception&) {
        throw UsageError("option --" + name + " expects an integer, got '" + *v + "'");
    }
}

void Args::allow_only(const std::set<std::string>& known) const {
    for (const auto& [k, _] : options_)
        if (!known.count(k)) throw UsageError("unknown option --" + k);
    for (const auto& f : flags_)
        if (!known.count(f)) throw UsageError("unknown option --" + f);
}

}  // namespace admin
