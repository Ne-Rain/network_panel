#include "tool.h"
#include <climits>
#include <cstddef>
#include <ctime>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

bool decode_base64(const std::string& encoded, std::string& decoded) {
    decoded.clear();
    // 标准 Base64 编码长度为 4 的倍数。
    if (encoded.empty() || encoded.size() % 4 != 0
        || encoded.size() > static_cast<std::size_t>(INT_MAX)) {
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
        const bool valid = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
            || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/';
        if (!valid)
            return false;
    }
    std::vector<unsigned char> buffer(encoded.size() / 4 * 3);
    // EVP_DecodeBlock() 每处理 4 个编码字符，会生成 3 字节输出，包含填充产生的字节，所以要根据末尾
    // = 的数量扣除它们。 返回 -1 表示解码错误
    int length = EVP_DecodeBlock(buffer.data(),
                                 reinterpret_cast<const unsigned char*>(encoded.data()),
                                 static_cast<int>(encoded.size()));
    if (length < 0)
        return false;
    decoded.assign(reinterpret_cast<const char*>(buffer.data()),
                   static_cast<std::size_t>(length) - padding);
    return true;
}

bool string_to_size_t(const std::string& s, std::size_t& value) {
    value = 0;
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

void append_json_string(std::string& out, const std::string& value) {
    constexpr char hex[] = "0123456789abcdef";
    out += '"';
    for (char ch : value) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20) {
            out += "\\u00";
            out += hex[byte >> 4];
            out += hex[byte & 0x0f];
        } else {
            if (ch == '"' || ch == '\\') {
                out += '\\';
            }
            out += ch;
        }
    }
    out += '"';
}

std::string make_local_time() {
    const std::time_t now = std::time(nullptr);
    std::tm local_time{};

    if (now == std::time_t(-1) || !::localtime_r(&now, &local_time)) {
        throw std::runtime_error("failed to get local time");
    }

    std::ostringstream out;
    out << std::put_time(&local_time, "%y/%m/%d %H:%M");
    return out.str();
}

std::string make_rand_id() {
    unsigned char bytes[32];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        return {};
    }

    const char* hex = "0123456789abcdef";
    std::string id;
    id.reserve(64);
    for (unsigned char byte : bytes) {
        id += hex[byte >> 4];
        id += hex[byte & 0x0f];
    }
    return id;
}

std::string encode_query_value(const std::string& value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string result;

    for (unsigned char c : value) {
        const bool unreserved = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';

        if (unreserved) {
            result += static_cast<char>(c);
        } else {
            result += '%';
            result += hex[c >> 4];
            result += hex[c & 0x0F];
        }
    }

    return result;
}

// 创建临时路径 mkstemp()生成一个唯一的临时文件名，并在同一步创建文件
std::string make_tmp_path(const std::string& tmp_dir) {
    const std::string pattern = tmp_dir + "netpanel-" + "-XXXXXX";

    // mkstemp 会原地替换末尾的六个 X，需要可写的字符数组
    std::vector<char> path(pattern.begin(), pattern.end());
    path.push_back('\0');
    const int fd = ::mkstemp(path.data());
    if (fd == -1) {
        throw std::system_error(errno, std::generic_category(), "Failed to create temp dir");
    }
    if (::close(fd) == -1) {
        const int error = errno;
        ::unlink(path.data());
        throw std::system_error(error, std::generic_category(), "Failed to close temp dir");
    }
    return std::string(path.data());
}