#include "file_catalog.hpp"
#include <vector>
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
    std::vector<FileRecord> loaded_file_list;
    try {
        loaded_accounts = load_accounts("config/groups.txt");
        loaded_file_list = load_files("config/files.txt");
    } catch (const std::exception& e) {
        std::cerr << "Failed to load accounts or files: " << e.what() << '\n';
        return 1;
    }

    const auto accounts = std::move(loaded_accounts);
    const auto file_list = std::move(loaded_file_list);
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

    server.Get("/files", [&accounts, &file_list](const httplib::Request& req, httplib::Response& res) {
        std::string group;
        const bool valid = req.get_header_value_count("Authorization") == 1 &&
                           authenticate_basic(req.get_header_value("Authorization"), accounts, group);
        if (!valid) {
            res.status = 401;
            res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
            res.set_content("authentication required", "text/plain");
            return;
        }
        std::vector<FileRecord> group_file_list =
            get_group_file_list(req.get_header_value(""), file_list, accounts, group);
        std::string request_group_file_list;
        for(const auto file : group_file_list){
            request_group_file_list += file.display_name + " ";
        }
        res.status = 200;
        res.set_content(request_group_file_list, "text/plain");
    });

    if (!server.listen("127.0.0.1", 8443)) {
        std::cerr << "Failed to listen\n";
        return 1;
    }
    return 0;
}