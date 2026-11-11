#include "auth.hpp"
#include "tool.h"
#include <algorithm>
#include <cctype>
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>



std::unordered_map<std::string, GroupAccount> load_accounts(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("file open failed");
    }
    std::unordered_map<std::string, GroupAccount> group_accounts;
    std::string line;
    std::size_t line_id = 0;
    while (std::getline(in, line)) {
        // 跳过空行，以及只包含空格、Tab、回车的行
        if (line.find_first_not_of(" \t\r") == std::string::npos) {
            continue;
        }
        ++line_id;
        GroupAccount group_account;
        std::istringstream iss(line);
        if (!(iss >> group_account.username >> group_account.password >> group_account.group)) {
            throw std::runtime_error("line_id: " + std::to_string(line_id) + " is illegal");
        }
        std::string tmp;
        if (iss >> tmp) { // 判断是否有多余字段
            throw std::runtime_error("line_id: " + std::to_string(line_id) + " is illegal");
        }
        if (group_accounts.find(group_account.username) != group_accounts.end()) {
            throw std::runtime_error("line_id: " + std::to_string(line_id) + " is already existed");
        }
        group_accounts.emplace(group_account.username, group_account);
    }
    if (in.bad()) { // 读取文件发生IO错误
        throw std::runtime_error("Failed to read account file: " + path);
    }
    return group_accounts;
}

bool authenticate_basic(const std::string& authorization,
                        const std::unordered_map<std::string, GroupAccount>& accounts, std::string& group) {
    group.clear();

    /*
    Basic YWxpY2U6cGFzczEyMw==
    Basic                       → 认证方式
    YWxpY2U6cGFzczEyMw==        → Base64 编码后的 alice:pass123
    'Basic'不区分大小写
    */
    auto separator = authorization.find(' ');
    if (separator == std::string::npos) {
        return false;
    }
    std::string scheme = authorization.substr(0, separator);
    // basic转小写
    std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (scheme != "basic") {
        return false;
    }
    // 找到第一个不是' '的字符，允许认证方式和凭证之间存在多个空格
    auto start = authorization.find_first_not_of(' ', separator);
    if (start == std::string::npos) {
        return false;
    }
    std::string encoded = authorization.substr(start);
    std::string credentials;
    if (!decode_base64(encoded, credentials)) {
        return false;
    }
    // Basic 不允许账号或密码包含控制字符
    for (unsigned char ch : credentials) {
        if (ch < 0x20 || ch == 0x7f)
            return false;
    }
    auto colon = credentials.find(':');
    if (colon == std::string::npos) {
        return false;
    }
    std::string username = credentials.substr(0, colon);
    std::string password = credentials.substr(colon + 1);
    auto it = accounts.find(username);
    if (it == accounts.end()) {
        return false;
    }
    if (it->second.password != password) {
        return false;
    }
    group = it->second.group;
    return true;
}