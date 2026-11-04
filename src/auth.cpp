#include "auth.hpp"
#include <algorithm>
#include <cctype>
#include <climits>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <vector>

bool decode_base64(const std::string& encoded, std::string& decoded) {
    decoded.clear();
    // 标准 Base64 编码长度为 4 的倍数。
    if (encoded.empty() || encoded.size() % 4 != 0 || encoded.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    // 末尾最多两个 '='，用于填充。
    std::size_t padding = 0;
    if (encoded.back() == '=')
        ++padding;
    if (encoded[encoded.size() - 2] == '=')
        ++padding;
    // 凭证中只允许 Base64 字符，'=' 只能出现在末尾。
    for (std::size_t i = 0; i < encoded.size() - padding; ++i) {
        const unsigned char ch = encoded[i];
        const bool valid = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                           ch == '+' || ch == '/';
        if (!valid)
            return false;
    }
    std::vector<unsigned char> buffer(encoded.size() / 4 * 3);
    // EVP_DecodeBlock() 每处理 4 个编码字符，会生成 3 字节输出，包含填充产生的字节，所以要根据末尾 =
    // 的数量扣除它们。 返回 -1 表示解码错误
    int length = EVP_DecodeBlock(buffer.data(), reinterpret_cast<const unsigned char*>(encoded.data()),
                                 static_cast<int>(encoded.size()));
    if (length < 0)
        return false;
    decoded.assign(reinterpret_cast<const char*>(buffer.data()), static_cast<std::size_t>(length) - padding);
    return true;
}

std::unordered_map<std::string, GroupAccount> load_accounts(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw;
    }
    std::unordered_map<std::string, GroupAccount> group_accounts;
    std::string line;
    while (std::getline(in, line)) {
        GroupAccount group_account;
        std::istringstream iss(line);
        iss >> group_account.username >> group_account.password >> group_account.group;
        if (group_accounts.find(group_account.username) == group_accounts.end()) {
            group_accounts.emplace(group_account.username, group_account);
        }
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
    if(it == accounts.end()){
        return false;
    }
    if(it->second.password != password){
        return false;
    }
    group = it->second.group;
    return true;
}