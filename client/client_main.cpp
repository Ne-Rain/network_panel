#include <sstream>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <chrono>
#include <openssl/rand.h>
#include <string>
#include <unordered_map>

#include "httplib.h"

static const std::string host = "192.168.110.51";
static const int port = 8843;
static const std::string ca_path = "./certs/ca.crt";

using SessionClock = std::chrono::steady_clock;
struct Session {
    std::string username;
    std::string password;
    std::string group = "PUBLIC";
    SessionClock::time_point expires_at;
};
static std::unordered_map<std::string, Session> sessions;
static std::mutex sessions_mtx;

// 使用RAND_bytes为会话生成唯一Cookie编号
static std::string make_session_id() {
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

enum class SessionState { Missing, Invalid, Valid };
// 获取当前会话Cookie
static SessionState load_session(const httplib::Request& req, Session& out) {
    std::istringstream cookies(req.get_header_value("Cookie"));
    const std::string prefix = "netpanel_session=";
    std::string item;

    while (std::getline(cookies, item, ';')) {
        const auto start = item.find_first_not_of(" \t");
        if (start == std::string::npos || item.compare(start, prefix.size(), prefix) != 0) {
            continue;
        }

        const auto id = item.substr(start + prefix.size());
        std::lock_guard<std::mutex> lock(sessions_mtx);
        const auto it = sessions.find(id);

        if (it == sessions.end()) {
            return SessionState::Invalid;
        }
        if (it->second.expires_at <= SessionClock::now()) {
            sessions.erase(it);
            return SessionState::Invalid;
        }

        out = it->second;
        return SessionState::Valid;
    }

    return SessionState::Missing;
}

static void clear_session_cookie(httplib::Response& res) {
    res.set_header("Set-Cookie", "netpanel_session=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0");
}

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

// 登录接口
static void handle_login(const httplib::Request& req, httplib::Response& res) {
    const auto username = req.get_param_value("username");
    const auto password = req.get_param_value("password");
    if (username.empty()) {
        res.status = 400;
        return;
    }

    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    client.set_basic_auth(username, password);

    std::string group = "PUBLIC";
    auto who = client.Get("/whoami");
    if (who->status != 200) {
        group = who->body;
    }

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
    const auto id = make_session_id();
    if (id.empty()) {
        res.status = 500;
        return;
    }
    {
        std::lock_guard<std::mutex> lock(sessions_mtx);
        const auto expires_at = SessionClock::now() + std::chrono::hours(1);
        if (!sessions.emplace(id, Session{username, password, group, expires_at}).second) {
            res.status = 500;
            return;
        }
    }
    std::string return_res = "{" + username + "," + group + "," + res.body + "}";
    res.set_header("Set-Cookie", "netpanel_session=" + id + "; Path=/api; HttpOnly; SameSite=Strict; Max-Age=3600");
    res.set_content(return_res, "text/plain");
}

// 文件列表接口
static void handle_files(const httplib::Request& req, httplib::Response& res) {
    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    Session session;
    const auto state = load_session(req, session);
    if (state == SessionState::Valid) {
        client.set_basic_auth(session.username, session.password);
    } else if (state == SessionState::Invalid) {
        clear_session_cookie(res);
    }

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
    std::istringstream input(result->body);
    std::string username = session.username.empty() ? "" : session.username;
    std::string json = "[";
    json += "{\"username\":";
    append_json_string(json, username);
    json += ",\"group\":";
    append_json_string(json, session.group);
    std::string id;
    std::string name;
    while (input >> id) {
        if (!(input >> name) || id.find_first_not_of("0123456789") != std::string::npos) {
            res.status = 502;
            return;
        }
        json += ",\"id\":";
        append_json_string(json, id);
        json += ",\"name\":";
        append_json_string(json, name);
        json += '}';
    }
    json += ']';
    res.set_content(json, "application/json");
}

// 下载接口
static void handle_download(const httplib::Request& req, httplib::Response& res) {
    const auto id = req.matches[1].str();
    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    Session session;
    const auto state = load_session(req, session);
    if (state == SessionState::Valid) {
        client.set_basic_auth(session.username, session.password);
    } else if (state == SessionState::Invalid) {
        clear_session_cookie(res);
    }

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
        return;
    }
    const auto dispostion = result->get_header_value("Content-Disposition");
    if (!dispostion.empty()) {
        res.set_header("Content-Disposition", dispostion);
    }
    auto content_type = result->get_header_value("Content-Type");
    if (content_type.empty()) {
        content_type = "application/octet-stream";
    }
    res.set_content(std::move(result->body), content_type);
}

// 上传接口
static void handle_upload(const httplib::Request& req, httplib::Response& res) {
    const auto filename = req.get_param_value("name");
    httplib::SSLClient client(host, port);
    client.set_ca_cert_path(ca_path);
    Session session;
    const auto state = load_session(req, session);

    if (state != SessionState::Valid) {
        if (state == SessionState::Invalid) {
            clear_session_cookie(res);
        }
        res.status = 401;
        return;
    }

    client.set_basic_auth(session.username, session.password);
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
    if (result->status != 201) {
        return;
    }
    std::istringstream input(result->body);
    std::string json = "";
    bool first = true;
    std::string id;
    while (input >> id) {
        if (id.empty() || id.find_first_not_of("0123456789") != std::string::npos) {
            res.status = 502;
            return;
        }
        if (!first) {
            json += ',';
        }
        first = false;
        json += "{\"id\":";
        append_json_string(json, id);
        json += '}';
    }
    res.set_content(json, "application/json");
}

int main() {
    httplib::Server local;
    if (!local.set_mount_point("/", "./client/web")) {
        std::cerr << "Failed to find webpage\n";
    }
    std::cout << "http://127.0.0.1:8080/\n";

    local.Post("/api/login", handle_login);
    local.Get("/api/files", handle_files);
    local.Get("/api/files/([0-9]+)", handle_download);
    local.Post("/api/files", handle_upload);

    if (!local.listen("127.0.0.1", 8080)) {
        std::cerr << "Failed to listen 8080\n";
        return 1;
    }

    return 0;
}