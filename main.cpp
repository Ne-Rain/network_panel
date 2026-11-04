#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <iostream>

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

    // 2. 注册请求处理函数
    server.Get("/hello", [](const httplib::Request& request, httplib::Response& response) {
        response.status = 200;
        response.set_content("hello", "text/plain");
    });

    if (!server.listen("127.0.0.1", 8443)) {
        std::cerr << "监听启动失败\n";
        return 1;
    }
    return 0;
}