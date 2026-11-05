#include "tool.h"
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <limits>
#include <openssl/evp.h>
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

bool string_to_size_t(const std::string& s, std::size_t& value) {
    constexpr size_t max = std::numeric_limits<std::size_t>::max();
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c < '0' || c > '9')
            return false; // 非法字符
        unsigned digit = static_cast<unsigned>(c - '0');
        if (value > (max - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    return true;
}