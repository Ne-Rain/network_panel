#include <sstream>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_map>

#include "device_discovery.hpp"
#include "device_identity.hpp"
#include "httplib.h"

static constexpr int local_port = 8080;

static void verify_remote_peer(httplib::SSLClient& client,
                               const std::string& expected_fingerprint) {
    client.set_session_verifier([expected_fingerprint](httplib::tls::session_t session) {
        using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
        Certificate certificate(SSL_get1_peer_certificate(static_cast<SSL*>(session)), &X509_free);
        return matches_device_certificate(certificate.get(), expected_fingerprint)
            ? httplib::SSLVerifierResponse::CertificateAccepted
            : httplib::SSLVerifierResponse::CertificateRejected;
    });
}

using SessionClock = std::chrono::steady_clock;
struct Session {
    std::string username;
    std::string password;
    std::string group = "PUBLIC";
    SessionClock::time_point expires_at;
    std::string server_fingerprint;
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
static SessionState
load_session(const httplib::Request& req, Session& out, const std::string& server_fingerprint) {
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
        if (it->second.expires_at <= SessionClock::now()
            || it->second.server_fingerprint != server_fingerprint) {
            sessions.erase(it);
            return SessionState::Invalid;
        }

        out = it->second;
        return SessionState::Valid;
    }

    return SessionState::Missing;
}

static void clear_session_cookie(httplib::Response& res) {
    res.set_header("Set-Cookie",
                   "netpanel_session=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0");
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

static constexpr char trusted_fingerprint_path[] = "certs/trusted-server.sha256";

static std::string read_trusted_fingerprint() {
    errno = 0;
    std::ifstream file(trusted_fingerprint_path);
    if (!file && errno == ENOENT) {
        return {};
    }
    std::string fingerprint, extra;
    if (!(file >> fingerprint) || file >> extra || file.bad() || fingerprint.size() != 64
        || fingerprint.find_first_not_of("0123456789abcdef") != std::string::npos) {
        throw std::runtime_error("reading trusted server fingerprint failed");
    }
    return fingerprint;
}

static void save_trusted_fingerprint(const std::string& fingerprint) {
    char temporary[] = "certs/.trusted-server-XXXXXX";
    const int fd = mkstemp(temporary);
    if (fd < 0) {
        throw std::runtime_error("creating trusted server fingerprint file failed");
    }
    const auto data = fingerprint + '\n';
    auto* file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        std::remove(temporary);
        throw std::runtime_error("opening trusted server fingerprint file failed");
    }
    const bool written = std::fwrite(data.data(), 1, data.size(), file) == data.size()
        && std::fflush(file) == 0 && fsync(fd) == 0;
    const bool closed = std::fclose(file) == 0;
    if (!written || !closed || std::rename(temporary, trusted_fingerprint_path) != 0) {
        std::remove(temporary);
        throw std::runtime_error("saving trusted server fingerprint failed");
    }
}

class LocalDiscovery {
public:
    explicit LocalDiscovery(const std::string& trusted) : trusted_(trusted) {}

    void discover(httplib::Response& res) {
        std::lock_guard<std::mutex> lock(mutex_);
        candidates_.clear();
        candidates_ = discover_servers();
        reply(res);
    }

    void trust(const std::string& fingerprint, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (candidates_.size() != 1 || candidates_.front().fingerprint != fingerprint) {
            res.status = 409;
            return;
        }
        if (trusted_ != fingerprint) {
            save_trusted_fingerprint(fingerprint);
            trusted_ = fingerprint;
        }
        reply(res);
    }

    bool target(RemoteTarget& result) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (candidates_.size() != 1 || candidates_.front().fingerprint != trusted_) {
            return false;
        }
        result = candidates_.front();
        return true;
    }

private:
    void reply(httplib::Response& res) const {
        if (candidates_.empty()) {
            res.set_content("{\"state\":\"missing\"}", "application/json");
            return;
        }
        if (candidates_.size() != 1) {
            res.set_content("{\"state\":\"multiple\"}", "application/json");
            return;
        }
        const auto& target = candidates_.front();
        std::string json = "{\"state\":";
        append_json_string(json, target.fingerprint == trusted_ ? "ready" : "untrusted");
        json += ",\"name\":";
        append_json_string(json, target.name);
        json += ",\"host\":";
        append_json_string(json, target.host);
        json += ",\"port\":" + std::to_string(target.port);
        json += ",\"fingerprint\":";
        append_json_string(json, target.fingerprint);
        json += '}';
        res.set_content(json, "application/json");
    }

    std::mutex mutex_;
    std::string trusted_;
    std::vector<RemoteTarget> candidates_;
};

static bool is_local_browser(const httplib::Request& req) {
    const auto host = req.get_header_value("Host");
    const auto port = std::to_string(local_port);
    return (host == "127.0.0.1:" + port || host == "localhost:" + port)
        && req.get_header_value("Origin") == "http://" + host;
}

static bool make_file_listing(const std::string& body, const Session* session, std::string& json) {
    json = "{\"username\":";
    if (session) {
        append_json_string(json, session->username);
        json += ",\"group\":";
        append_json_string(json, session->group);
    } else {
        json += "null,\"group\":null";
    }
    json += ",\"files\":[";

    std::istringstream input(body);
    std::string id;
    std::string name;
    bool first = true;

    while (input >> id) {
        if (!(input >> name) || id.find_first_not_of("0123456789") != std::string::npos) {
            return false;
        }

        if (!first) {
            json += ',';
        }
        first = false;

        json += "{\"id\":";
        append_json_string(json, id);
        json += ",\"name\":";
        append_json_string(json, name);
        json += '}';
    }

    json += "]}";
    return true;
}

// 登录接口
static void
handle_login(const httplib::Request& req, httplib::Response& res, const RemoteTarget& target) {
    const auto username = req.get_param_value("username");
    const auto password = req.get_param_value("password");
    if (username.empty()) {
        res.status = 400;
        return;
    }

    httplib::SSLClient client(target.host, target.port);
    verify_remote_peer(client, target.fingerprint);
    client.set_basic_auth(username, password);

    std::string group = "PUBLIC";
    auto who = client.Get("/whoami");
    if (!who) {
        res.status = 502;
        return;
    }
    if (who->status != 200) {
        res.status = 502;
        return;
    }
    group = who->body;
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
    const auto expires_at = SessionClock::now() + std::chrono::hours(1);
    const Session session{username, password, group, expires_at, target.fingerprint};

    std::string json;
    if (!make_file_listing(result->body, &session, json)) {
        res.status = 502;
        return;
    }
    {
        std::lock_guard<std::mutex> lock(sessions_mtx);
        if (!sessions.emplace(id, session).second) {
            res.status = 500;
            return;
        }
    }
    res.set_header("Set-Cookie",
                   "netpanel_session=" + id
                       + "; Path=/api; HttpOnly; SameSite=Strict; Max-Age=3600");
    res.set_content(json, "application/json");
}

// 文件列表接口
static void
handle_files(const httplib::Request& req, httplib::Response& res, const RemoteTarget& target) {
    httplib::SSLClient client(target.host, target.port);
    verify_remote_peer(client, target.fingerprint);
    Session session;
    const auto state = load_session(req, session, target.fingerprint);
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
    const Session* identity = state == SessionState::Valid ? &session : nullptr;

    std::string json;
    json = "{\"username\":";
    if (identity) {
        append_json_string(json, identity->username);
        json += ",\"group\":";
        append_json_string(json, identity->group);
    } else {
        json += "null,\"group\":null";
    }
    json += ",\"files\":" + result->body;
    res.set_content(json, "application/json");
}

// 下载接口
static void
handle_download(const httplib::Request& req, httplib::Response& res, const RemoteTarget& target) {
    const auto id = req.matches[1].str();
    httplib::SSLClient client(target.host, target.port);
    verify_remote_peer(client, target.fingerprint);
    Session session;
    const auto state = load_session(req, session, target.fingerprint);
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
static void
handle_upload(const httplib::Request& req, httplib::Response& res, const RemoteTarget& target) {
    const auto filename = req.get_param_value("name");
    httplib::SSLClient client(target.host, target.port);
    verify_remote_peer(client, target.fingerprint);
    Session session;
    const auto state = load_session(req, session, target.fingerprint);

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
    std::string trusted_fingerprint;
    try {
        const auto identity = load_or_create_device_identity();
        std::cout << "Device certificate SHA-256: " << identity.fingerprint << '\n';
        trusted_fingerprint = read_trusted_fingerprint();
    } catch (const std::exception& error) {
        std::cerr << "Client initialization failed: " << error.what() << '\n';
        return 1;
    }

    LocalDiscovery discovery(trusted_fingerprint);
    httplib::Server local;
    if (!local.set_mount_point("/", "./client/web")) {
        std::cerr << "Failed to find webpage\n";
    }
    std::cout << "http://127.0.0.1:" << local_port << "/\n";

    local.Post("/api/discover", [&](const httplib::Request& req, httplib::Response& res) {
        if (!is_local_browser(req)) {
            res.status = 403;
            return;
        }
        discovery.discover(res);
    });
    local.Post("/api/discover/trust", [&](const httplib::Request& req, httplib::Response& res) {
        if (!is_local_browser(req)) {
            res.status = 403;
            return;
        }
        discovery.trust(req.body, res);
    });

    const auto with_target = [&discovery](auto handler) {
        return [&discovery, handler](const httplib::Request& req, httplib::Response& res) {
            RemoteTarget target{};
            if (!discovery.target(target)) {
                res.status = 503;
                return;
            }
            handler(req, res, target);
        };
    };
    local.Post("/api/login", with_target(handle_login));
    local.Get("/api/files", with_target(handle_files));
    local.Get("/api/files/([0-9]+)", with_target(handle_download));
    local.Post("/api/files", with_target(handle_upload));

    if (!local.listen("127.0.0.1", local_port)) {
        std::cerr << "Failed to listen " << local_port << '\n';
        return 1;
    }

    return 0;
}
