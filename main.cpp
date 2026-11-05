#include "file_catalog.hpp"
#include "tool.h"
#include <cstddef>
#include <string>
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
    std::unordered_map<std::size_t, FileRecord> loaded_file_list;
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
        std::size_t auth_header_vaule_count = req.get_header_value_count("Authorization");
        if (auth_header_vaule_count == 0) {
            group = "PUBLIC";
        } else if (auth_header_vaule_count > 1 ||
                   !authenticate_basic(req.get_header_value("Authorization"), accounts, group)) {
            res.status = 401;
            res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
            res.set_content("authentication required", "text/plain");
            return;
        }
        std::vector<FileRecord> group_file_list = get_group_file_list(file_list, group);
        std::string request_group_file_list;
        for (const auto file : group_file_list) {
            std::string tmp = std::to_string(file.file_id) + " " + file.display_name + " ";
            request_group_file_list += tmp;
        }
        res.status = 200;
        res.set_content(request_group_file_list, "text/plain");
    });

    server.Get("/file/([0-9]+))", [&accounts, &file_list](const httplib::Request& req, httplib::Response& res) {
        std::string group;
        std::size_t auth_header_vaule_count = req.get_header_value_count("Authorization");
        if (auth_header_vaule_count == 0) {
            group = "PUBLIC";
        } else if (auth_header_vaule_count > 1 ||
                   !authenticate_basic(req.get_header_value("Authorization"), accounts, group)) {
            res.status = 401;
            res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
            res.set_content("authentication required", "text/plain");
            return;
        }
        const std::string id_text = req.matches[1].str();
        std::size_t file_id = 0;
        if (!string_to_size_t(id_text, file_id)) {
            res.status = 401;
            return;
        }
        auto it = file_list.find(file_id);
        if (it == file_list.end()) {
            res.status = 401;
            return;
        }
        if (it->second.owner_group != group && it->second.owner_group != "PUBLIC") {
            res.status = 404;
            return;
        }
        auto dot = it->second.display_name.rfind('.');
        std::string suffix{};
        if (dot != std::string::npos && dot + 1 < it->second.display_name.size()) {
            suffix = it->second.display_name.substr(dot + 1); // 提取后缀名
        }
        res.status = 200;
        res.set_header("Content-Disposition", "attachment; filename=\"" + it->second.display_name + "\"");
        res.set_file_content(it->second.storage_path, "application/" + suffix);
    });

    if (!server.listen("127.0.0.1", 8443)) {
        std::cerr << "Failed to listen\n";
        return 1;
    }
    return 0;
}