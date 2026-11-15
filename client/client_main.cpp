#include "download_file.hpp"
#include <ios>
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_map>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "device_discovery.hpp"
#include "device_identity.hpp"
#include "httplib.h"
#include "task_record.hpp"
#include "tool.h"

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
    std::string session_id;
    std::string username;
    std::string password;
    std::string group = "PUBLIC";
    SessionClock::time_point expires_at;
    std::string server_fingerprint;
};
static std::unordered_map<std::string, Session> sessions;
static std::mutex sessions_mtx;

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

namespace {
// 登录接口
void handle_login(const httplib::Request& req, httplib::Response& res, const RemoteTarget& target) {
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
    if (who->status == 401) {
        res.status = 401;
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
    const auto id = make_rand_id();
    if (id.empty()) {
        res.status = 500;
        return;
    }
    const auto expires_at = SessionClock::now() + std::chrono::hours(1);
    const Session session{id, username, password, group, expires_at, target.fingerprint};

    std::string json;
    json = "{\"username\":";
    append_json_string(json, session.username);
    json += ",\"group\":";
    append_json_string(json, session.group);

    json += ",\"files\":" + result->body;
    json += '}';
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
void handle_files(const httplib::Request& req, httplib::Response& res, const RemoteTarget& target) {
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
    json += ",\"files\":" + result->body + '}';
    res.set_content(json, "application/json");
}

// 下载任务可以属于登录会话，也可以属于独立游客 Cookie。
static std::string download_owner(const httplib::Request& req,
                                  httplib::Response& res,
                                  const RemoteTarget& target,
                                  bool create) {
    Session session;
    const auto state = load_session(req, session, target.fingerprint);
    if (state == SessionState::Valid)
        return "session:" + session.session_id;
    if (state == SessionState::Invalid)
        clear_session_cookie(res);
    std::istringstream cookies(req.get_header_value("Cookie"));
    std::string item, guest;
    const std::string prefix = "netpanel_download_guest=";
    while (std::getline(cookies, item, ';')) {
        const auto start = item.find_first_not_of(" \t");
        if (start != std::string::npos && item.compare(start, prefix.size(), prefix) == 0)
            guest = item.substr(start + prefix.size());
    }
    if (guest.size() != 64 || guest.find_first_not_of("0123456789abcdef") != std::string::npos)
        guest.clear();
    if (guest.empty() && create) {
        guest = make_rand_id();
        if (!guest.empty())
            res.set_header("Set-Cookie",
                           "netpanel_download_guest=" + guest
                               + "; Path=/api; HttpOnly; SameSite=Strict");
    }
    return guest.empty() ? std::string() : "guest:" + guest + ":" + target.fingerprint;
}

// 创建下载任务
void handle_download_task(const httplib::Request& req,
                          httplib::Response& res,
                          const RemoteTarget& target,
                          std::unordered_map<std::string, DownloadTask>& tasks,
                          std::mutex& mtx) {
    const auto owner = download_owner(req, res, target, true);
    if (owner.empty()) {
        res.status = 500;
        return;
    }
    DownloadTask record{};
    record.owner_session_id = owner;
    std::lock_guard<std::mutex> lock(mtx);
    for (int attempt = 0; attempt < 32; ++attempt) {
        record.task_id = make_rand_id();
        if (record.task_id.empty())
            break;
        if (tasks.emplace(record.task_id, record).second) {
            res.set_content(record.task_id, "text/plain");
            res.status = 200;
            return;
        }
    }
    res.status = 500;
}

// 查询下载任务状态
void handle_download_task_state(const httplib::Request& req,
                                httplib::Response& res,
                                const RemoteTarget& target,
                                std::unordered_map<std::string, DownloadTask>& tasks,
                                std::mutex& mtx) {
    const auto owner = download_owner(req, res, target, false);
    DownloadTask record{};
    {
        std::lock_guard<std::mutex> lock(mtx);
        const auto it = tasks.find(req.matches[1].str());
        if (owner.empty() || it == tasks.end() || it->second.owner_session_id != owner) {
            res.status = 404;
            return;
        }
        record = it->second;
    }
    std::string json = "{\"task_id\":";
    append_json_string(json, record.task_id);
    json += ",\"received_bytes\":";
    append_json_string(json, std::to_string(record.received_bytes));
    json += ",\"total_bytes\":";
    if (record.total_known)
        append_json_string(json, std::to_string(record.total_bytes));
    else
        json += "null";
    json += ",\"state\":";
    append_json_string(json, state_to_string(record.state));
    json += "}";
    res.set_content(json, "application/json");
}

// 删除下载任务：取消后移除；进入保存阶段后拒绝取消
void handle_delete_download_task(const httplib::Request& req,
                                 httplib::Response& res,
                                 const RemoteTarget& target,
                                 std::unordered_map<std::string, DownloadTask>& tasks,
                                 std::mutex& mtx) {
    const auto owner = download_owner(req, res, target, false);
    std::lock_guard<std::mutex> lock(mtx);
    const auto it = tasks.find(req.matches[1].str());
    if (owner.empty() || it == tasks.end() || it->second.owner_session_id != owner) {
        res.status = 404;
        return;
    }
    if (it->second.state != TaskState::Restart && it->second.state != TaskState::Running) {
        res.status = 409;
        return;
    }
    tasks.erase(it);
    res.status = 204;
}

// 下载接口：接收并保存文件，204 表示最终文件已经发布
void handle_download(const httplib::Request& req,
                     httplib::Response& res,
                     const RemoteTarget& target,
                     std::unordered_map<std::string, DownloadTask>& tasks,
                     std::mutex& mtx) {
    const auto owner = download_owner(req, res, target, false);
    const auto task_id = req.get_param_value("task_id");
    const auto target_path = req.get_param_value("target_path");
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = tasks.find(task_id);
        if (owner.empty() || it == tasks.end() || it->second.owner_session_id != owner) {
            res.status = 404;
            return;
        }
        if (it->second.state != TaskState::Restart) {
            res.status = 409;
            return;
        }
        it->second.state = TaskState::Running;
    }
    // 所有失败都更新终态；已取消的记录不会重新插入。
    const auto fail = [&](int status) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = tasks.find(task_id);
        if (it != tasks.end())
            it->second.state = TaskState::Failed;
        res.status = status;
    };
    if (target_path.empty() || target_path.find('\0') != std::string::npos) {
        fail(400);
        return;
    }
    try {
        DownloadFile output(target_path);
        httplib::SSLClient client(target.host, target.port);
        verify_remote_peer(client, target.fingerprint);
        client.set_read_timeout(30, 0);
        Session session;
        if (load_session(req, session, target.fingerprint) == SessionState::Valid)
            client.set_basic_auth(session.username, session.password);
        int remote_status = 0;
        std::size_t expected = 0, received = 0;
        bool invalid_headers = false, write_failed = false, length_mismatch = false;
        auto on_header = [&](const httplib::Response& response) {
            remote_status = response.status;
            if (remote_status != 200)
                return false;
            const auto text = response.get_header_value("Content-Length");
            if (text.empty() || !string_to_size_t(text, expected)) {
                invalid_headers = true;
                return false;
            }
            std::lock_guard<std::mutex> lock(mtx);
            auto it = tasks.find(task_id);
            if (it == tasks.end())
                return false;
            it->second.total_bytes = expected;
            it->second.total_known = true;
            return true;
        };
        auto on_data = [&](const char* data, std::size_t size) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (tasks.find(task_id) == tasks.end())
                    return false;
            }
            if (received > expected || size > expected - received) {
                length_mismatch = true;
                return false;
            }
            if (!output.write(data, size)) {
                write_failed = true;
                return false;
            }
            received += size;
            std::lock_guard<std::mutex> lock(mtx);
            auto it = tasks.find(task_id);
            if (it == tasks.end())
                return false;
            it->second.received_bytes = received;
            return true;
        };
        auto progress = [&](std::size_t, std::size_t) {
            std::lock_guard<std::mutex> lock(mtx);
            return tasks.find(task_id) != tasks.end();
        };
        auto result = client.Get("/file/" + req.matches[1].str(), on_header, on_data, progress);
        {
            std::lock_guard<std::mutex> lock(mtx);
            if (tasks.find(task_id) == tasks.end()) {
                res.status = 409;
                return;
            }
        }
        if (remote_status != 0 && remote_status != 200) {
            fail(remote_status);
            return;
        }
        if (write_failed) {
            fail(500);
            return;
        }
        if (!result || invalid_headers || length_mismatch || received != expected) {
            fail(502);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mtx);
            auto it = tasks.find(task_id);
            if (it == tasks.end()) {
                res.status = 409;
                return;
            }
            it->second.state = TaskState::Confirming;
        }
        output.publish();
        {
            std::lock_guard<std::mutex> lock(mtx);
            tasks.at(task_id).state = TaskState::Success;
        }
        res.status = 204;
    } catch (const std::invalid_argument&) {
        fail(400);
    } catch (const std::system_error& error) {
        fail(error.code() == std::errc::file_exists ? 409 : 500);
    } catch (const std::exception&) {
        fail(500);
    }
}

// 上传接口
void handle_upload(const httplib::Request& req,
                   httplib::Response& res,
                   const RemoteTarget& target,
                   std::unordered_map<std::string, UploadTask>& upload_task_set,
                   std::mutex& upload_task_mtx) {
    const auto source_path = req.get_param_value("source_path");
    const auto task_id = req.get_param_value("task_id");
    if (source_path.empty() || source_path.find('\0') != std::string::npos) {
        res.status = 400;
        return;
    }
    // 同时识别 Windows 和 Linux 路径分隔符
    const auto separator = source_path.find_last_of("/\\");
    const auto filename = source_path.substr(separator == std::string::npos ? 0 : separator + 1);

    if (filename.empty()) {
        res.status = 400;
        return;
    }
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
    std::ifstream input;

#ifdef _WIN32
    // Windows UTF-8 中文路径
    const int wide_length = MultiByteToWideChar(CP_UTF8,
                                                MB_ERR_INVALID_CHARS,
                                                source_path.data(),
                                                static_cast<int>(source_path.size()),
                                                nullptr,
                                                0);

    if (wide_length <= 0) {
        res.status = 400;
        return;
    }

    std::wstring wide_path(wide_length, L'\0');
    MultiByteToWideChar(CP_UTF8,
                        MB_ERR_INVALID_CHARS,
                        source_path.data(),
                        static_cast<int>(source_path.size()),
                        &wide_path[0],
                        wide_length);

    input.open(wide_path.c_str(), std::ios::binary | std::ios::ate);
#else
    // ate表示打开后立即把读指针移到文件末尾
    input.open(source_path, std::ios::binary | std::ios::ate);
#endif

    if (!input.is_open()) {
        res.status = 400;
        res.set_content("Cannot open source file", "text/plain");
        return;
    }
    const auto end = input.tellg(); // 返回当前读取位置
    if (end == std::ifstream::pos_type(-1)) {
        res.status = 500;
        return;
    }
    const auto file_size = static_cast<std::streamoff>(end);
    if (file_size < 0
        || static_cast<unsigned long long>(file_size) > std::numeric_limits<std::size_t>::max()) {
        res.status = 400;
        return;
    }
    const auto content_length = static_cast<std::size_t>(file_size);

    // 将读指针移动到距离文件开头 0 字节的位置，std::ios::beg：以文件开头为基准
    input.seekg(0, std::ios::beg);

    if (!input) {
        res.status = 500;
        return;
    }

    std::unique_lock<std::mutex> lock(upload_task_mtx);
    auto it = upload_task_set.find(task_id);
    if (it == upload_task_set.end() || it->second.owner_session_id != session.session_id) {
        res.status = 404;
        return;
    }
    if (it->second.state != TaskState::Restart) {
        res.status = 409;
        return;
    }
    it->second.sent_bytes = 0;
    it->second.total_bytes = content_length;
    it->second.state = content_length == 0 ? TaskState::Confirming : TaskState::Running;
    lock.unlock();

    // 分块持续发送
    std::array<char, 64 * 1024> buffer{};
    bool source_read_failed = false;

    httplib::ContentProvider provider =
        [&](std::size_t offset, std::size_t remaining, httplib::DataSink& sink) -> bool {
        const auto count = std::min(buffer.size(), remaining);

        if (count == 0) {
            return false;
        }

        // 开始磁盘读取前检查取消
        {
            std::lock_guard<std::mutex> lock(upload_task_mtx);
            if (upload_task_set.find(task_id) == upload_task_set.end()) {
                return false;
            }
        }

        input.clear();
        input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!input) {
            source_read_failed = true;
            return false;
        }

        input.read(buffer.data(), static_cast<std::streamsize>(count));

        if (input.bad() || input.gcount() != static_cast<std::streamsize>(count)) {
            source_read_failed = true;
            return false;
        }

        // 读取期间也可能取消，所以发送前再检查一次。
        {
            std::lock_guard<std::mutex> lock(upload_task_mtx);
            auto it = upload_task_set.find(task_id);
            if (it == upload_task_set.end()) {
                return false;
            }

            // 在发送最后一块之前进入不可取消阶段。
            if (offset + count == content_length) {
                it->second.state = TaskState::Confirming;
            }
        }

        return sink.write(buffer.data(), count);
    };
    auto progress = [&](std::size_t current, std::size_t total) {
        std::lock_guard<std::mutex> lock(upload_task_mtx);
        auto it = upload_task_set.find(task_id);
        if (it == upload_task_set.end()) {
            return false;
        }
        it->second.sent_bytes = current;
        return true;
    };
    auto result = client.Post("/files?name=" + encode_query_value(filename),
                              content_length,
                              provider,
                              "application/octet-stream",
                              progress);

    {
        std::lock_guard<std::mutex> lk(upload_task_mtx);
        auto task_it = upload_task_set.find(task_id);
        if (task_it == upload_task_set.end()
            || task_it->second.owner_session_id != session.session_id) {
            res.status = 404;
            return;
        }
        if (!result) {
            task_it->second.state = TaskState::Failed;
            res.status = source_read_failed ? 500 : 502;
            return;
        }
        if (result->status == 401) {
            res.status = 401;
            task_it->second.state = TaskState::Failed;
            return;
        }
        res.status = result->status;
        if (result->status != 201) {
            task_it->second.state = TaskState::Failed;
            return;
        }
        task_it->second.state = TaskState::Success;
    }

    std::istringstream res_input(result->body);
    std::string json = "";
    bool first = true;
    std::string id;
    while (res_input >> id) {
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
        json += ",\"task_id\":";
        append_json_string(json, task_id);
    }
    json += '}';
    res.set_content(json, "application/json");
}

// 删除接口
void handle_delete(const httplib::Request& req,
                   httplib::Response& res,
                   const RemoteTarget& target) {
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
    const auto id = req.matches[1].str();
    auto result = client.Delete("/file/" + id);
    if (!result) {
        res.status = 502;
        return;
    }
    res.status = result->status;
    if (result->status != 204) {
        return;
    }
}

// 创建上传任务
void handle_task(const httplib::Request& req,
                 httplib::Response& res,
                 const RemoteTarget& target,
                 std::unordered_map<std::string, UploadTask>& upload_task_set,
                 std::mutex& upload_task_mtx) {
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
    UploadTask record{};
    record.owner_session_id = session.session_id;
    auto create_record_id_time = std::chrono::steady_clock::now();
    std::unique_lock<std::mutex> lock(upload_task_mtx);
    while (true) {
        std::string tmp_id = make_rand_id();
        if (upload_task_set.find(tmp_id) == upload_task_set.end()) {
            record.task_id = tmp_id;
            upload_task_set.emplace(tmp_id, record);
            break;
        }
        // 设置2s创建任务期限
        if (std::chrono::steady_clock::now() - create_record_id_time > std::chrono::seconds(2)) {
            res.status = 402;
            return;
        }
    }
    lock.unlock();
    res.status = 200;
    res.set_content(record.task_id, "application/octet-stream");
}

// 查询任务状态
void handle_task_state(const httplib::Request& req,
                       httplib::Response& res,
                       const RemoteTarget& target,
                       std::unordered_map<std::string, UploadTask>& upload_task_set,
                       std::mutex& upload_task_mtx) {
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
    std::string task_id = req.matches[1].str();
    std::size_t sent_bytes;
    std::size_t total_bytes;
    TaskState task_state;
    {
        std::lock_guard<std::mutex> lock(upload_task_mtx);
        auto it = upload_task_set.find(task_id);
        if (it == upload_task_set.end() || it->second.owner_session_id != session.session_id) {
            res.status = 404;
            return;
        }
        sent_bytes = it->second.sent_bytes;
        total_bytes = it->second.total_bytes;
        task_state = it->second.state;
    }
    std::string json = "{\"task_id\":";
    append_json_string(json, task_id);
    json += ",\"sent_bytes\":";
    append_json_string(json, std::to_string(sent_bytes));
    json += ",\"total_bytes\":";
    append_json_string(json, std::to_string(total_bytes));
    json += ",\"state\":";
    append_json_string(json, state_to_string(task_state));
    json += "}";
    res.status = 200;
    res.set_content(json, "application/json");
}

// 删除上传任务
void handle_delete_task(const httplib::Request& req,
                        httplib::Response& res,
                        const RemoteTarget& target,
                        std::unordered_map<std::string, UploadTask>& upload_task_set,
                        std::mutex& upload_task_mtx) {
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
    std::string task_id = req.matches[1].str();
    {
        std::lock_guard<std::mutex> lock(upload_task_mtx);
        auto it = upload_task_set.find(task_id);
        if (it == upload_task_set.end() || it->second.owner_session_id != session.session_id) {
            res.status = 404;
            return;
        }
        if (it->second.state == TaskState::Restart || it->second.state == TaskState::Running) {
            upload_task_set.erase(it);
            res.status = 204;
            return;
        }
    }
    res.status = 409;
}
} // namespace

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
    local.set_payload_max_length(std::size_t{5} * 1024 * 1024 * 1024 * 1024);
    if (!local.set_mount_point("/", "./client/web")) {
        std::cerr << "Failed to find webpage\n";
    }
    std::cout << "http://127.0.0.1:" << local_port << "/\n";

    std::unordered_map<std::string, UploadTask> upload_task_set; // 任务编号集合
    std::mutex upload_task_mtx;
    std::unordered_map<std::string, DownloadTask> download_task_set;
    std::mutex download_task_mtx;

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
    local.Post("/api/files/([0-9]+)",
               [&discovery, &download_task_set, &download_task_mtx](const httplib::Request& req,
                                                                    httplib::Response& res) {
                   if (!is_local_browser(req)) {
                       res.status = 403;
                       return;
                   }
                   RemoteTarget target{};
                   if (!discovery.target(target)) {
                       res.status = 503;
                       return;
                   }
                   handle_download(req, res, target, download_task_set, download_task_mtx);
               });
    local.Post("/api/download-task/",
               [&discovery, &download_task_set, &download_task_mtx](const httplib::Request& req,
                                                                    httplib::Response& res) {
                   if (!is_local_browser(req)) {
                       res.status = 403;
                       return;
                   }
                   RemoteTarget target{};
                   if (!discovery.target(target)) {
                       res.status = 503;
                       return;
                   }
                   handle_download_task(req, res, target, download_task_set, download_task_mtx);
               });
    local.Get(
        "/api/download-task/([0-9a-f]{64})",
        [&discovery, &download_task_set, &download_task_mtx](const httplib::Request& req,
                                                             httplib::Response& res) {
            if (!is_local_browser(req)) {
                res.status = 403;
                return;
            }
            RemoteTarget target{};
            if (!discovery.target(target)) {
                res.status = 503;
                return;
            }
            handle_download_task_state(req, res, target, download_task_set, download_task_mtx);
        });
    local.Delete(
        "/api/download-task/([0-9a-f]{64})",
        [&discovery, &download_task_set, &download_task_mtx](const httplib::Request& req,
                                                             httplib::Response& res) {
            if (!is_local_browser(req)) {
                res.status = 403;
                return;
            }
            RemoteTarget target{};
            if (!discovery.target(target)) {
                res.status = 503;
                return;
            }
            handle_delete_download_task(req, res, target, download_task_set, download_task_mtx);
        });
    local.Delete("/api/files/([0-9]+)", with_target(handle_delete));
    local.Post("/api/files",
               [&discovery, &upload_task_set, &upload_task_mtx](const httplib::Request& req,
                                                                httplib::Response& res) {
                   RemoteTarget target{};
                   if (!discovery.target(target)) {
                       res.status = 503;
                       return;
                   }

                   handle_upload(req, res, target, upload_task_set, upload_task_mtx);
               });
    local.Post("/api/task/",
               [&discovery, &upload_task_set, &upload_task_mtx](const httplib::Request& req,
                                                                httplib::Response& res) {
                   RemoteTarget target{};
                   if (!discovery.target(target)) {
                       res.status = 503;
                       return;
                   }
                   handle_task(req, res, target, upload_task_set, upload_task_mtx);
               });
    local.Get("/api/task/([0-9a-f]{64})",
              [&discovery, &upload_task_set, &upload_task_mtx](const httplib::Request& req,
                                                               httplib::Response& res) {
                  RemoteTarget target{};
                  if (!discovery.target(target)) {
                      res.status = 503;
                      return;
                  }
                  handle_task_state(req, res, target, upload_task_set, upload_task_mtx);
              });
    local.Delete("/api/task/([0-9a-f]{64})",
                 [&discovery, &upload_task_set, &upload_task_mtx](const httplib::Request& req,
                                                                  httplib::Response& res) {
                     RemoteTarget target{};
                     if (!discovery.target(target)) {
                         res.status = 503;
                         return;
                     }
                     handle_delete_task(req, res, target, upload_task_set, upload_task_mtx);
                 });
    if (!local.listen("127.0.0.1", local_port)) {
        std::cerr << "Failed to listen " << local_port << '\n';
        return 1;
    }

    return 0;
}
