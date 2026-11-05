#include "file_catalog.hpp"
#include "tool.h"
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <ios>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "auth.hpp"
#include "httplib.h"
#include <exception>
#include <iostream>
#include <unordered_map>

static const std::regex valid_name(R"([A-Za-z0-9][A-Za-z0-9._-]{0,127})");

// 分配文件编号
std::size_t reserve_file_id(std::mutex& id_mtx, std::size_t last_file_id) {
    std::lock_guard<std::mutex> lock(id_mtx);
    if (last_file_id == std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error("file_id is limited");
    }
    const std::size_t next_id = last_file_id + 1;
    const char* path = "./config/last_file_id.txt";
    const char* tmp_path = "./config/last_file_id.txt.tmp";
    std::ofstream out(tmp_path, std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Failed to open tmp_file");
    }
    out << next_id << '\n';
    out.close();
    if (!out || std::rename(tmp_path, path) != 0) {
        std::remove(tmp_path);
        throw std::runtime_error("Failed to save file_id");
    }
    last_file_id = next_id;
    return next_id;
}

/**创建临时上传路径
    mkstemp()生成一个唯一的临时文件名，并在同一步创建文件
*/
std::string make_upload_tmp_path(const std::string& upload_dir, std::size_t id) {
    const std::string pattern = upload_dir + "./upload-" + std::to_string(id) + "-XXXXXX";

    // mkstemp 会原地替换末尾的六个 X，需要可写的字符数组
    std::vector<char> path(pattern.begin(), pattern.end());
    path.push_back('\0');
    const int fd = ::mkstemp(path.data());
    if (fd == -1) {
        throw std::system_error(errno, std::generic_category(), "Failed to create temp upload_dir");
    }
    if (::close(fd) == -1) {
        const int error = errno;
        ::unlink(path.data());
        throw std::system_error(error, std::generic_category(), "Failed to close temp upload_dir");
    }
    return std::string(path.data());
}

bool publish_upload(std::size_t id, std::string name, std::string group, std::string temp_path,
                    std::string upload_dir) {
    std::string path = upload_dir + "/" + std::to_string(id);
    std::ofstream out(temp_path, std::ios::trunc);
    if (!out || std::rename(temp_path.c_str(), path.c_str()) != 0) {
        std::remove(temp_path.c_str());
        throw std::runtime_error("Failed to save file");
    }
    FileRecord file_record{id, name, group, path};
    std::ofstream file_list_out("./config/files.txt", std::ios::app);
    if (!file_list_out) {
        throw std::runtime_error("Failed to open file_list");
    }
    file_list_out << id << ' ' << name << ' ' << group << ' ' << path << '\n';
    out.close();
    if(!out){
        throw std::runtime_error("Failed to writer file_list");
    }
    return true;
}

int main() {

    // 1. 创建https服务对象
    httplib::SSLServer server("./certs/server.crt", "./certs/server.key");
    if (!server.is_valid()) {
        std::cerr << "HTTPS 初始化失败，请检查证书和私钥\n";
        return 1;
    }

    std::mutex file_id_mtx;
    std::size_t last_file_id; // 最后的文件编号
    std::string upload_dir;   // 文件上传路径
    std::ifstream last_file_id_in("./config/last_file_id.txt");
    if (!last_file_id_in) {
        throw std::runtime_error("last_file_id_file open failed");
    }
    std::string line;
    if (std::getline(last_file_id_in, line)) {
        std::size_t file_id;
        if (string_to_size_t(line, file_id)) {
            std::lock_guard<std::mutex> lock(file_id_mtx);
            last_file_id = file_id;
        } else {
            std::cerr << "Failed to load last_file_id\n";
            return 1;
        }
    }
    std::ifstream upload_dir_in("./config/upload_dir.txt");
    if (!upload_dir_in) {
        throw std::runtime_error("upload_dir_file open failed");
    }
    std::string tmp_line;
    if (std::getline(upload_dir_in, tmp_line)) {
        upload_dir = tmp_line;
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

    server.Get("/file/([0-9]+)", [&accounts, &file_list](const httplib::Request& req, httplib::Response& res) {
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
            res.status = 400;
            return;
        }
        auto it = file_list.find(file_id);
        if (it == file_list.end()) {
            res.status = 404;
            return;
        }
        if (it->second.owner_group != group && it->second.owner_group != "PUBLIC") {
            res.status = 404;
            return;
        }
        res.status = 200;
        res.set_header("Content-Disposition", "attachment; filename=\"" + it->second.display_name + "\"");
        res.set_file_content(it->second.storage_path, "application/octet-stream");
    });

    server.Post("/files",
                [&accounts, &file_list, &file_id_mtx, last_file_id, upload_dir](
                    const httplib::Request& req, httplib::Response& res, const httplib::ContentReader& reader) {
                    std::string group;
                    if (req.get_header_value_count("Authorization") != 1 ||
                        !authenticate_basic(req.get_header_value("Authorization"), accounts, group)) {
                        res.status = 401;
                        res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
                        return;
                    }
                    const auto name = req.get_param_value("name");
                    if (name.empty()) {
                        res.status = 400;
                        return;
                    }
                    if (!std::regex_match(name, valid_name)) {
                        res.status = 400;
                        return;
                    }
                    const auto id = reserve_file_id(file_id_mtx, last_file_id);
                    const auto temp_path = make_upload_tmp_path(upload_dir, id);

                    std::ofstream out(temp_path, std::ios::binary);
                    if (!out) {
                        res.status = 500;
                        return;
                    }
                    const bool received = reader([&](const char* data, std::size_t size) {
                        out.write(data, static_cast<std::streamsize>(size));
                        return static_cast<bool>(out);
                    });
                    out.close();
                    if (!out || !received) {
                        std::remove(temp_path.c_str());
                        if (res.status < 400) {
                            res.status = !out ? 500 : 400;
                        }
                        return;
                    }

                    if (!publish_upload(id, name, group, temp_path, upload_dir)) {
                        std::remove(temp_path.c_str());
                        res.status = 500;
                        return;
                    }
                    res.status = 201;
                    res.set_content(std::to_string(id), "text/plain");
                });

    if (!server.listen("127.0.0.1", 8443)) {
        std::cerr << "Failed to listen\n";
        return 1;
    }
    return 0;
}