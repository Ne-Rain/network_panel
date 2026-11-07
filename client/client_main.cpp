#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <string>

#include "httplib.h"

static const std::string host = "10.139.13.142";
static const int port = 8843;
static const std::string ca_path = "./certs/ca.crt";

int main() {
    httplib::Server local;
    if (!local.set_mount_point("/", "./client/web")) {
        std::cerr << "Failed to find webpage\n";
    }
    std::cout << "http://127.0.0.1:8080/\n";

    local.Post("/api/login", [&](const httplib::Request& req, httplib::Response& res) {
        const auto username = req.get_param_value("username");
        const auto password = req.get_param_value("password");
        if (username.empty()) {
            res.status = 400;
            return;
        }
        httplib::SSLClient client(host, port);
        client.set_ca_cert_path(ca_path);
        client.set_basic_auth(username, password);

        auto result = client.Get("/files");

        if (!result) {
            res.status = 502;
            return;
        }
        if(result->status == 401){
            res.status = 401;
            return;
        }
        if(result->status != 200){
            res.status = 502;
            return;
        }
        res.set_content(result->body, "text/plain");
    });

    if (!local.listen("127.0.0.1", 8080)) {
        std::cerr << "Failed to listen 8080\n";
        return 1;
    }

    return 0;
}