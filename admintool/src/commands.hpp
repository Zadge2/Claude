#pragma once

#include <string>
#include <vector>

namespace admin {

// Each command group receives the arguments following its name (e.g. for
// "admintool svc start Spooler" it receives {"start", "Spooler"}).
int cmd_sys(const std::vector<std::string>& argv);
int cmd_users(const std::vector<std::string>& argv);
int cmd_svc(const std::vector<std::string>& argv);
int cmd_logs(const std::vector<std::string>& argv);

}  // namespace admin
