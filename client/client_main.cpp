#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <string>

#include "httplib.h"

static const std::string host = "10.139.13.142";
static const int port = 8843;
static const std::string ca_path = "./certs/ca.crt";
static const std::string username = "nerain";
static const std::string password = "12345";

int main() {
    httplib::Server local;
    if (!local.set_mount_point("/", "./client/web")) {
        std::cerr << "Failed to find webpage\n";
    }
    std::cout << "http://127.0.0.1:8080/\n";
    if (!local.listen("127.0.0.1", 8080)) {
        std::cerr << "Failed to listen 8080\n";
        return 1;
    }
    // httplib::SSLClient client(host, port);
    // client.set_ca_cert_path(ca_path);
    // client.set_basic_auth(username, password);

    // auto result = client.Get("/files");

    // if (!result) {
    //     std::cerr << "请求失败：" << httplib::to_string(result.error()) << '\n';
    //     return 1;
    // }

    // std::cout << "HTTP " << result->status << '\n';
    // std::cout << result->body << '\n';
    return 0;
}