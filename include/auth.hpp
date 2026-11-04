#pragma once

#include <string>
#include <unordered_map>

struct GroupAccount {
    std::string username;
    std::string password;
    std::string group;
};

// 启动时读取账号文件
std::unordered_map<std::string, GroupAccount> load_accounts(const std::string& path);

// 身份验证
bool authenticate_basic(const std::string& authorization,
                        const std::unordered_map<std::string, GroupAccount>& accounts, std::string& group);