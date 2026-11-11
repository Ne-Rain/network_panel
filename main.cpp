#include <cstdint>
#include <iomanip>
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "auth.hpp"
#include "device_discovery.hpp"
#include "device_identity.hpp"
#include "file_catalog.hpp"
#include "httplib.h"
#include "tool.h"

#include <cstddef>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <ios>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

static const std::string host = "0.0.0.0";
static const int port = 8843;

static const std::regex valid_name(R"([A-Za-z0-9](?:[ A-Za-z0-9._-]{0,126}[A-Za-z0-9._-])?)");
static const std::string config_last_file_id = "./config/last_file_id.txt";
static const std::string config_files = "./config/files.txt";
static const std::string config_upload_dir = "./config/upload_dir.txt";
static const std::string config_groups = "./config/groups.txt";

static void append_json_string(std::string& out, const std::string& value) {
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

static void make_file_listing(FileRecord record, std::string& json) {
    json += "{\"id\":";
    append_json_string(json, std::to_string(record.file_id));
    json += ",\"name\":";
    append_json_string(json, record.display_name);
    json += ",\"size_bytes\":";
    append_json_string(json, std::to_string(record.size_bytes));
    json += ",\"type\":";
    append_json_string(json, file_type_to_string(record.type));
    json += ",\"uploadedAt\":";
    append_json_string(json, record.uploadedAt);
    json += "}";
}

// 分配文件编号
std::size_t reserve_file_id(std::mutex& id_mtx, std::size_t& last_file_id) {
    std::lock_guard<std::mutex> lock(id_mtx);
    if (last_file_id == std::numeric_limits<std::size_t>::max()) {
        throw std::overflow_error("file_id is limited");
    }
    const std::size_t next_id = last_file_id + 1;

    const char* path = config_last_file_id.c_str();
    std::string tmp = config_last_file_id + ".tmp";
    const char* tmp_path = tmp.c_str();

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

/**创建临时路径
    mkstemp()生成一个唯一的临时文件名，并在同一步创建文件
*/
std::string make_tmp_path(const std::string& tmp_dir, std::size_t id) {
    const std::string pattern = tmp_dir + "upload-" + std::to_string(id) + "-XXXXXX";

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

void publish_upload(std::size_t id,
                    const std::string& name,
                    std::uint64_t file_size,
                    const std::string& group,
                    const std::string& temp_path,
                    const std::string& upload_dir,
                    std::unordered_map<std::size_t, FileRecord>& file_list,
                    std::mutex& file_mtx) {
    // 写完完整的临时表 → 创建正式文件 → 替换磁盘表 → 更新内存表
    std::lock_guard<std::mutex> lock(file_mtx);

    std::string final_path;  // 上传文件存储路径
    std::string catalog_tmp; // 临时磁盘文件表路径
    bool final_created = false;

    try {
        final_path = upload_dir + std::to_string(id);

        // 准备完整的新文件表，当前内存表仍可保留
        auto next_files = file_list;
        FileType file_type = get_file_type(name);
        std::string local_time = make_local_time();
        if (!next_files
                 .emplace(id,
                          FileRecord{id, name, file_size, file_type, local_time, group, final_path})
                 .second) {
            throw std::runtime_error("Duplicate file ID");
        }

        catalog_tmp = make_tmp_path("./config/", 0);
        std::ofstream out(catalog_tmp, std::ios::trunc);
        if (!out) {
            throw std::runtime_error("Failed to open temporary file catalog");
        }

        // 把内存表写入新磁盘文件表
        for (const auto& entry : next_files) {
            const auto& file = entry.second;
            out << file.file_id << ' ' << std::quoted(file.display_name) << ' ' << file.size_bytes
                << ' ' << file_type_to_string(file.type) << ' ' << std::quoted(file.uploadedAt)
                << ' ' << file.owner_group << ' ' << file.storage_path << '\n';
        }
        out.close();
        if (!out) {
            throw std::runtime_error("Failed to write temporary file catalog");
        }

        // link 保留已有目标文件。只有成功时才标记为本次创建
        if (::link(temp_path.c_str(), final_path.c_str()) != 0) {
            const int error = errno;
            throw std::system_error(error, std::generic_category(), "Failed to publish upload");
        }
        final_created = true;

        // 替换磁盘文件表
        if (std::rename(catalog_tmp.c_str(), config_files.c_str()) != 0) {
            const int error = errno;
            throw std::system_error(error,
                                    std::generic_category(),
                                    "Failed to replace file catalog");
        }

        // 更新内存文件表
        file_list.swap(next_files);
    } catch (...) {
        if (!catalog_tmp.empty()) {
            std::remove(catalog_tmp.c_str());
        }
        if (final_created) {
            std::remove(final_path.c_str());
        }
        std::remove(temp_path.c_str());
        throw;
    }

    std::remove(temp_path.c_str());
}

static void handle_whoami(const httplib::Request& req,
                          httplib::Response& res,
                          const std::unordered_map<std::string, GroupAccount>& accounts) {
    std::string group;
    const bool valid = req.get_header_value_count("Authorization") == 1
        && authenticate_basic(req.get_header_value("Authorization"), accounts, group);
    if (!valid) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
        res.set_content("authentication required", "text/plain");
        return;
    }
    res.status = 200;
    res.set_content(group, "text/plain");
}

static void handle_get_file(const httplib::Request& req,
                            httplib::Response& res,
                            const std::unordered_map<std::string, GroupAccount>& accounts,
                            std::unordered_map<std::size_t, FileRecord>& file_list,
                            std::mutex& file_mtx) {
    std::string group;
    std::size_t auth_header_vaule_count = req.get_header_value_count("Authorization");
    if (auth_header_vaule_count == 0) {
        group = "PUBLIC";
    } else if (auth_header_vaule_count > 1
               || !authenticate_basic(req.get_header_value("Authorization"), accounts, group)) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
        res.set_content("authentication required", "text/plain");
        return;
    }
    std::unique_lock<std::mutex> lock(file_mtx);
    std::vector<FileRecord> group_file_list = get_group_file_list(file_list, group);
    lock.unlock();
    std::string json_file = "[";
    bool first = true;
    for (const auto file : group_file_list) {
        if (!first) {
            json_file += ',';
        }
        make_file_listing(file, json_file);
        first = false;
    }
    json_file += ']';
    res.status = 200;
    res.set_content(json_file, "application/json");
}

static void handle_download(const httplib::Request& req,
                            httplib::Response& res,
                            const std::unordered_map<std::string, GroupAccount>& accounts,
                            std::unordered_map<std::size_t, FileRecord>& file_list,
                            std::mutex& file_mtx) {
    std::string group;
    std::size_t auth_header_vaule_count = req.get_header_value_count("Authorization");
    if (auth_header_vaule_count == 0) {
        group = "PUBLIC";
    } else if (auth_header_vaule_count > 1
               || !authenticate_basic(req.get_header_value("Authorization"), accounts, group)) {
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
    std::unique_lock<std::mutex> lock(file_mtx);
    auto it = file_list.find(file_id);
    if (it == file_list.end()) {
        res.status = 404;
        return;
    }
    const FileRecord record = it->second;
    lock.unlock();
    if (record.owner_group != group && record.owner_group != "PUBLIC") {
        res.status = 404;
        return;
    }
    res.status = 200;
    res.set_header("Content-Disposition", "attachment; filename=\"" + record.display_name + "\"");
    res.set_file_content(record.storage_path, "application/octet-stream");
}

static void handle_upload(const httplib::Request& req,
                          httplib::Response& res,
                          const httplib::ContentReader& reader,
                          const std::unordered_map<std::string, GroupAccount>& accounts,
                          std::unordered_map<std::size_t, FileRecord>& file_list,
                          std::mutex& file_id_mtx,
                          std::size_t& last_file_id,
                          std::mutex& file_mtx,
                          std::string upload_dir) {
    std::string group;
    if (req.get_header_value_count("Authorization") != 1
        || !authenticate_basic(req.get_header_value("Authorization"), accounts, group)) {
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
    const auto temp_path = make_tmp_path(upload_dir, id);

    std::ofstream out(temp_path, std::ios::binary);
    if (!out) {
        res.status = 500;
        return;
    }
    std::uint64_t file_size = 0;
    const bool received = reader([&](const char* data, std::size_t size) {
        out.write(data, static_cast<std::streamsize>(size));
        if (out) {
            file_size += size;
            return true;
        }
        return false;
    });
    out.close();
    if (!out || !received) {
        std::remove(temp_path.c_str());
        if (res.status < 400) {
            res.status = !out ? 500 : 400;
        }
        return;
    }
    publish_upload(id, name, file_size, group, temp_path, upload_dir, file_list, file_mtx);
    res.status = 201;
    res.set_content(std::to_string(id), "text/plain");
}

static void handle_delete(const httplib::Request& req,
                          httplib::Response& res,
                          const std::unordered_map<std::string, GroupAccount>& accounts,
                          std::unordered_map<std::size_t, FileRecord>& file_list,
                          std::mutex& file_mtx) {
    std::string group;
    if (req.get_header_value_count("Authorization") != 1
        || !authenticate_basic(req.get_header_value("Authorization"), accounts, group)) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"netpanel\"");
        return;
    }
    const std::string id_text = req.matches[1].str();
    std::size_t file_id = 0;
    if (!string_to_size_t(id_text, file_id)) {
        res.status = 400;
        return;
    }
    std::unique_lock<std::mutex> lock(file_mtx);
    auto it = file_list.find(file_id);
    if (it == file_list.end() || it->second.owner_group != group) {
        res.status = 404;
        return;
    }

    std::string catalog_tmp; // 临时磁盘文件表路径
    std::string backups; // 备份磁盘文件表路径（文件表更新后，但是文件删除失败，恢复原文件表）
    bool preserve_backup = false;
    try {
        auto next_files = file_list;
        const auto memory_to_disk = [&](std::string path) {
            std::ofstream out(path, std::ios::trunc);
            if (!out) {
                throw std::runtime_error("Failed to open temporary file catalog");
            }

            // 把内存表写入新磁盘文件表
            for (const auto& entry : next_files) {
                const auto& file = entry.second;
                out << file.file_id << ' ' << std::quoted(file.display_name) << ' '
                    << file.size_bytes << ' ' << file_type_to_string(file.type) << ' '
                    << std::quoted(file.uploadedAt) << ' ' << file.owner_group << ' '
                    << file.storage_path << '\n';
            }
            out.close();
            if (!out) {
                throw std::runtime_error("Failed to write temporary file catalog");
            }
        };
        backups = make_tmp_path("./config/", 0);
        memory_to_disk(backups);

        next_files.erase(file_id);
        catalog_tmp = make_tmp_path("./config/", 0);

        memory_to_disk(catalog_tmp);

        // 替换磁盘文件表
        if (std::rename(catalog_tmp.c_str(), config_files.c_str()) != 0) {
            const int error = errno;
            throw std::system_error(error,
                                    std::generic_category(),
                                    "Failed to replace file catalog");
        }
        if (std::remove(it->second.storage_path.c_str()) != 0) { // 删除目标文件
            // 删除失败用备份文件表恢复
            if (std::rename(backups.c_str(), config_files.c_str()) != 0) {
                const int error = errno;
                preserve_backup = true;

                std::cerr << "Catalog recovery failed. Backup preserved at: " << backups << '\n';

                throw std::system_error(error,
                                        std::generic_category(),
                                        "Failed to restore file catalog");
            }
            res.status = 500;
            throw std::runtime_error("Failed to delete target file");
        }

        // 更新内存文件表
        file_list.swap(next_files);
        std::remove(backups.c_str());
    } catch (...) {
        if (!catalog_tmp.empty()) {
            std::remove(catalog_tmp.c_str());
        }
        if (!backups.empty() && !preserve_backup) {
            std::remove(backups.c_str());
        }
        throw;
    }
    res.status = 204;
}

int main() {
    DeviceIdentity identity;
    try {
        identity = load_or_create_device_identity();
        std::cout << "Device certificate SHA-256: " << identity.fingerprint << '\n';
    } catch (const std::exception& error) {
        std::cerr << "Device identity initialization failed: " << error.what() << '\n';
        return 1;
    }

    // 1. 创建https服务对象
    httplib::SSLServer server(identity.pem_path.c_str(), identity.pem_path.c_str());
    if (!server.is_valid()) {
        std::cerr << "HTTPS 初始化失败，请检查证书和私钥\n";
        return 1;
    }

    std::mutex file_id_mtx;
    std::size_t last_file_id = 0; // 最后的文件编号
    std::string upload_dir;       // 文件上传路径
    std::ifstream last_file_id_in(config_last_file_id);
    if (!last_file_id_in) {
        throw std::runtime_error("last_file_id_file open failed");
    }
    std::string line;
    if (!std::getline(last_file_id_in, line) || line.empty()
        || !string_to_size_t(line, last_file_id)) {
        std::cerr << "Invalid last_file_id.txt\n";
        return 1;
    }

    std::ifstream upload_dir_in(config_upload_dir);
    if (!upload_dir_in) {
        throw std::runtime_error("upload_dir_file open failed");
    }
    std::string tmp_line;
    if (!std::getline(upload_dir_in, upload_dir) || upload_dir.empty()) {
        std::cerr << "Invalid upload directory\n";
        return 1;
    }
    if (upload_dir.back() != '/') {
        upload_dir += '/';
    }

    std::unordered_map<std::string, GroupAccount> loaded_accounts;
    std::unordered_map<std::size_t, FileRecord> loaded_file_list;
    try {
        loaded_accounts = load_accounts(config_groups);
        loaded_file_list = load_files(config_files);
    } catch (const std::exception& e) {
        std::cerr << "Failed to load accounts or files: " << e.what() << '\n';
        return 1;
    }

    // 保证 配置表中最大文件编号 >= 实际文件表的最大编号
    for (const auto& entry : loaded_file_list) {
        if (entry.first > last_file_id) {
            std::cerr << "last_file_id.txt is behind the file catalog\n";
            return 1;
        }
    }

    const auto accounts = std::move(loaded_accounts); // 用户组表
    auto file_list = std::move(loaded_file_list);     // 文件表
    std::mutex file_mtx;                              // 文件表锁
    // 2. 注册请求处理函数
    server.Get("/whoami", [&accounts](const httplib::Request& req, httplib::Response& res) {
        handle_whoami(req, res, accounts);
    });
    server.Get(
        "/files",
        [&accounts, &file_list, &file_mtx](const httplib::Request& req, httplib::Response& res) {
            handle_get_file(req, res, accounts, file_list, file_mtx);
        });
    server.Get(
        "/file/([0-9]+)",
        [&accounts, &file_list, &file_mtx](const httplib::Request& req, httplib::Response& res) {
            handle_download(req, res, accounts, file_list, file_mtx);
        });
    server.Post("/files",
                [&accounts, &file_list, &file_id_mtx, &last_file_id, &file_mtx, upload_dir](
                    const httplib::Request& req,
                    httplib::Response& res,
                    const httplib::ContentReader& reader) {
                    handle_upload(req,
                                  res,
                                  reader,
                                  accounts,
                                  file_list,
                                  file_id_mtx,
                                  last_file_id,
                                  file_mtx,
                                  upload_dir);
                });
    server.Delete(
        "/file/([0-9]+)",
        [&accounts, &file_list, &file_mtx](const httplib::Request& req, httplib::Response& res) {
            handle_delete(req, res, accounts, file_list, file_mtx);
        });

    if (!server.bind_to_port(host, port)) {
        std::cerr << "Failed to bind HTTPS port\n";
        return 1;
    }
    try {
        DiscoveryResponder discovery(port, identity.fingerprint);
        if (!server.listen_after_bind()) {
            std::cerr << "Failed to listen\n";
            return 1;
        }
    } catch (const std::exception& error) {
        std::cerr << "Discovery initialization failed: " << error.what() << '\n';
        return 1;
    }
    return 0;
}