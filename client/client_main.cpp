#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <string>

#include "httplib.h"

static const std::string host = "10.139.13.142";
static const int port = 8843;
static const std::string ca_path = "./certs/ca.crt";
static std::string username_record;
static std::string password_record;

// 登录接口
static void handle_login(const httplib::Request& req, httplib::Response& res) {
    const auto username = req.get_param_value("username");
    const auto password = req.get_param_value("password");
    if (username.empty()) {
        res.status = 400;
        return;
    }
    username_record = username;
    password_record = password;
    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    client.set_basic_auth(username_record, password_record);

    auto result = client.Get("/files");

    if (!result) {
        res.status = 502;
        return;
    }
    if (result->status == 401) {
        res.status = 401;
        return;
    }
    if (result->status != 200) {
        res.status = 502;
        return;
    }
    res.set_content(result->body, "text/plain");
}

// 文件列表接口
static void handle_files(const httplib::Request& req, httplib::Response& res) {
    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    client.set_basic_auth(username_record, password_record);

    auto result = client.Get("/files");

    if (!result) {
        res.status = 502;
        return;
    }
    if (result->status == 401) {
        res.status = 401;
        return;
    }
    if (result->status != 200) {
        res.status = 502;
        return;
    }
    res.status = 200;
    res.set_content(result->body, "text/json");
}

// 下载接口
static void handle_download(const httplib::Request& req, httplib::Response& res) {
    const auto id = req.get_param_value("id");
    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    client.set_basic_auth(username_record, password_record);
    auto result = client.Get("/file/" + id);
    if (!result) {
        res.status = 502;
        return;
    }
    if (result->status == 401) {
        res.status = 401;
        return;
    }
    res.status = result->status;
    if (result->status != 200) {
        res.status = 502;
        return;
    }
    const auto dispostion = result->get_header_value("Content-Disposition");
    if (!dispostion.empty()) {
        res.set_header("Content-Disposition", dispostion);
    }
    auto content_type = result->get_header_value("Content-Type");
    if(content_type.empty()){
        content_type = "application/octet-stream";
    }
    res.set_file_content(std::move(result->body), content_type);
}

// 上传接口
static void handle_upload(const httplib::Request& req, httplib::Response& res) {
    const auto filename = req.get_param_value("name");
    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    client.set_basic_auth(username_record, password_record);
    auto result = client.Post("/files?name=" + filename, req.body, "application/octet-stream");
    if (!result) {
        res.status = 502;
        return;
    }
    if (result->status == 401) {
        res.status = 401;
        return;
    }
    res.status = result->status;
    if (result->status != 200) {
        res.status = 502;
        return;
    }
    std::string res_content = "{\"id\":\"" + result->body + "\"}";
    res.set_content(res_content, "text/plain");
}

int main() {
    httplib::Server local;
    if (!local.set_mount_point("/", "./client/web")) {
        std::cerr << "Failed to find webpage\n";
    }
    std::cout << "http://127.0.0.1:8080/\n";

    local.Post("/api/login", handle_login);
    local.Post("/api/file/([0-9]+)", handle_files);
    local.Post("/api/files", handle_upload);

    if (!local.listen("127.0.0.1", 8080)) {
        std::cerr << "Failed to listen 8080\n";
        return 1;
    }

    return 0;
}