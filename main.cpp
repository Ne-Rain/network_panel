#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "auth.hpp"
#include "httplib.h"
#include <exception>
#include <iostream>
#include <unordered_map>

using std::cin;
using std::cout;
using std::endl;

int main() {

    // 1. 创建https服务对象
    httplib::SSLServer server("./certs/server.crt", "./certs/server.key");
    if (!server.is_valid()) {
        std::cerr << "HTTPS 初始化失败，请检查证书和私钥\n";
        return 1;
    }

    std::unordered_map<std::string, GroupAccount> loaded_accounts;
    try {
        loaded_accounts = load_accounts("config/groups.txt");
    } catch (const std::exception& e) {
        std::cerr << "加载账号失败: " << e.what() << '\n';
        return 1;
    }

    const auto accounts = std::move(loaded_accounts);
    // 2. 注册请求处理函数
    server.Get("/whoami", [&accounts](const httplib::Request& req, httplib::Response& res) {
        std::string group;
        const bool valid = req.get_header_value_count("Authorization") == 1 &&
                           authenticate_basic(req.get_header_value("Authorization"), accounts, group);
        if (!valid) {
            res.status = 401;
            res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
            res.set_content("authentication required", "text/plain");
            return;
        }
        res.status = 200;
        res.set_content(group, "text/plain");
    });

    if (!server.listen("127.0.0.1", 8443)) {
        std::cerr << "监听启动失败\n";
        return 1;
    }
    return 0;
}