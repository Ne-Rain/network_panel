#include "device_discovery.hpp"

#include <openssl/rand.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace {

constexpr char protocol[] = "NETPANEL/1";
constexpr char multicast_ip[] = "239.255.42.99";
constexpr int discovery_port = 38443;
using Clock = std::chrono::steady_clock;

#ifdef _WIN32
using Socket = SOCKET;
using SocketLength = int;
using PollDescriptor = WSAPOLLFD;
constexpr Socket invalid_socket = INVALID_SOCKET;
constexpr int receive_flags = 0;

void initialize_sockets() {
    struct Runtime {
        Runtime() {
            WSADATA data{};
            const int error = WSAStartup(MAKEWORD(2, 2), &data);
            if (error != 0) {
                throw std::system_error(error, std::system_category(), "initializing discovery sockets");
            }
        }
        ~Runtime() { WSACleanup(); }
    };
    static Runtime runtime;
}

void close_socket(Socket socket) { closesocket(socket); }
int poll_socket(PollDescriptor* socket, int timeout) { return WSAPoll(socket, 1, timeout); }
bool socket_interrupted() { return WSAGetLastError() == WSAEINTR; }
int set_socket_option(Socket socket, int level, int option, const void* value, int size) {
    return setsockopt(socket, level, option, static_cast<const char*>(value), size);
}
#else
using Socket = int;
using SocketLength = socklen_t;
using PollDescriptor = pollfd;
constexpr Socket invalid_socket = -1;
constexpr int receive_flags = MSG_TRUNC;
void initialize_sockets() {}
void close_socket(Socket socket) { close(socket); }
int poll_socket(PollDescriptor* socket, int timeout) { return poll(socket, 1, timeout); }
bool socket_interrupted() { return errno == EINTR; }
int set_socket_option(Socket socket, int level, int option, const void* value, int size) {
    return setsockopt(socket, level, option, value, static_cast<socklen_t>(size));
}
#endif

[[noreturn]] void socket_error(const char* operation) {
#ifdef _WIN32
    throw std::system_error(WSAGetLastError(), std::system_category(), operation);
#else
    throw std::system_error(errno, std::generic_category(), operation);
#endif
}

class UdpSocket {
public:
    UdpSocket() {
        initialize_sockets();
#ifdef _WIN32
        fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
        fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#endif
        if (fd_ == invalid_socket) {
            socket_error("creating discovery socket");
        }
    }
    ~UdpSocket() {
        if (fd_ != invalid_socket) {
            close_socket(fd_);
        }
    }
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    Socket get() const { return fd_; }
    Socket release() {
        const Socket fd = fd_;
        fd_ = invalid_socket;
        return fd;
    }

private:
    Socket fd_ = invalid_socket;
};

sockaddr_in address(std::uint32_t ip, int port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_port = htons(static_cast<unsigned short>(port));
    result.sin_addr.s_addr = ip;
    return result;
}

void bind_socket(Socket fd, int port) {
    const auto local = address(INADDR_ANY, port);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) !=
        0) {
        socket_error("binding discovery socket");
    }
}

std::vector<in_addr> multicast_interfaces() {
#ifdef _WIN32
    ULONG size = 16384;
    std::vector<unsigned char> buffer(size);
    ULONG error = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && error == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.resize(size);
        error = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (error != NO_ERROR && error != ERROR_NO_DATA) {
        throw std::system_error(error, std::system_category(), "listing discovery interfaces");
    }
    std::vector<in_addr> result;
    if (error == NO_ERROR) {
        for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
             adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp ||
                adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
                (adapter->Flags & IP_ADAPTER_NO_MULTICAST)) {
                continue;
            }
            for (auto* entry = adapter->FirstUnicastAddress; entry; entry = entry->Next) {
                if (entry->Address.lpSockaddr && entry->Address.lpSockaddr->sa_family == AF_INET) {
                    const auto ip = reinterpret_cast<sockaddr_in*>(entry->Address.lpSockaddr)->sin_addr;
                    const auto duplicate = std::find_if(result.begin(), result.end(),
                        [&](const in_addr& value) { return value.s_addr == ip.s_addr; });
                    if (duplicate == result.end()) result.push_back(ip);
                }
            }
        }
    }
#else
    ifaddrs* addresses = nullptr;
    if (getifaddrs(&addresses) != 0) {
        socket_error("listing discovery interfaces");
    }
    const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> entries(
        addresses, &freeifaddrs);
    std::vector<in_addr> result;
    for (auto* entry = entries.get(); entry; entry = entry->ifa_next) {
        constexpr unsigned int required = IFF_UP | IFF_MULTICAST;
        if (entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET &&
            (entry->ifa_flags & required) == required &&
            !(entry->ifa_flags & IFF_LOOPBACK)) {
            result.push_back(
                reinterpret_cast<const sockaddr_in*>(entry->ifa_addr)
                    ->sin_addr);
        }
    }
#endif
    if (result.empty()) {
        result.push_back(in_addr{INADDR_ANY});
    }
    return result;
}

bool is_hex(const std::string& value, std::size_t size) {
    return value.size() == size &&
           value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

std::string make_nonce() {
    unsigned char bytes[8];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        throw std::runtime_error("generating discovery nonce failed");
    }
    constexpr char hex[] = "0123456789abcdef";
    std::string nonce;
    for (const auto byte : bytes) {
        nonce += hex[byte >> 4];
        nonce += hex[byte & 0xf];
    }
    return nonce;
}

std::string device_name() {
    char name[65]{};
    if (gethostname(name, sizeof(name) - 1) != 0 || !name[0]) {
        return "NetPanel";
    }
    std::string result(name);
    for (char& ch : result) {
        if (ch < ' ' || ch > '~') {
            ch = '_';
        }
    }
    return result;
}

bool read_offer(const std::string& packet, const std::string& nonce,
                const sockaddr_in& sender, RemoteTarget& target) {
    std::istringstream input(packet);
    std::string version, command, response_nonce;
    if (!(input >> version >> command >> response_nonce >> target.port >>
          target.fingerprint) ||
        version != protocol || command != "OFFER" || response_nonce != nonce ||
        target.port <= 0 || target.port > 65535 ||
        !is_hex(target.fingerprint, 64)) {
        return false;
    }
    std::getline(input >> std::ws, target.name);
    if (target.name.empty() || target.name.size() > 64 ||
        std::any_of(target.name.begin(), target.name.end(),
                    [](char ch) { return ch < ' ' || ch > '~'; })) {
        return false;
    }
    char host[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &sender.sin_addr, host, sizeof(host))) {
        return false;
    }
    target.host = host;
    return true;
}

} // namespace

DiscoveryResponder::DiscoveryResponder(int https_port,
                                       const std::string& fingerprint) {
    UdpSocket socket;
    const int reuse = 1;
    if (set_socket_option(socket.get(), SOL_SOCKET, SO_REUSEADDR, &reuse,
                   sizeof(reuse)) != 0) {
        socket_error("setting discovery socket reuse");
    }
    bind_socket(socket.get(), discovery_port);
    bool joined = false;
    for (const auto& network_interface : multicast_interfaces()) {
        ip_mreq membership{};
        membership.imr_multiaddr.s_addr = inet_addr(multicast_ip);
        membership.imr_interface = network_interface;
        if (set_socket_option(socket.get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &membership,
                       sizeof(membership)) == 0) {
            joined = true;
        }
    }
    if (!joined) {
        socket_error("joining discovery multicast group");
    }

    const auto endpoint =
        std::to_string(https_port) + " " + fingerprint + " " + device_name();
    socket_ = socket.get();
    worker_ = std::thread(&DiscoveryResponder::respond, this, endpoint);
    socket.release();
}

DiscoveryResponder::~DiscoveryResponder() {
    stopping_ = true;
    worker_.join();
    close_socket(socket_);
}

void DiscoveryResponder::respond(const std::string& endpoint) {
    PollDescriptor pending{socket_, POLLIN, 0};
    while (!stopping_) {
        const int ready = poll_socket(&pending, 200);
        if (ready < 0 && !socket_interrupted()) {
            return;
        }
        if (ready > 0 && !(pending.revents & POLLIN)) {
            return;
        }
        if (ready <= 0 || stopping_) {
            continue;
        }

        char buffer[256];
        sockaddr_in sender{};
        SocketLength size = sizeof(sender);
        const auto received =
            recvfrom(socket_, buffer, sizeof(buffer), receive_flags,
                     reinterpret_cast<sockaddr*>(&sender), &size);
        if (received <= 0 || received > static_cast<int>(sizeof(buffer))) {
            continue;
        }
        std::istringstream input(
            std::string(buffer, static_cast<std::size_t>(received)));
        std::string version, command, nonce, extra;
        if (!(input >> version >> command >> nonce) || input >> extra ||
            version != protocol || command != "DISCOVER" ||
            !is_hex(nonce, 16)) {
            continue;
        }
        const auto response =
            std::string(protocol) + " OFFER " + nonce + " " + endpoint;
        sendto(socket_, response.data(), response.size(), 0,
               reinterpret_cast<const sockaddr*>(&sender), size);
    }
}

std::vector<RemoteTarget> discover_servers() {
    UdpSocket socket;
    bind_socket(socket.get(), 0);
    const unsigned int ttl = 1;
    if (set_socket_option(socket.get(), IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
                   sizeof(ttl)) != 0) {
        socket_error("limiting discovery multicast scope");
    }
    const auto group = address(inet_addr(multicast_ip), discovery_port);
    const auto interfaces = multicast_interfaces();
    const auto nonce = make_nonce();
    const auto query = std::string(protocol) + " DISCOVER " + nonce;
    std::vector<RemoteTarget> devices;
    PollDescriptor pending{socket.get(), POLLIN, 0};

    for (int attempt = 0; attempt < 3 && devices.empty(); ++attempt) {
        bool sent = false;
        for (const auto& network_interface : interfaces) {
            if (set_socket_option(socket.get(), IPPROTO_IP, IP_MULTICAST_IF,
                           &network_interface, sizeof(network_interface)) == 0 &&
                sendto(socket.get(), query.data(), query.size(), 0,
                       reinterpret_cast<const sockaddr*>(&group),
                       sizeof(group)) == static_cast<int>(query.size())) {
                sent = true;
            }
        }
        if (!sent) {
            socket_error("sending discovery query");
        }

        const auto deadline = Clock::now() + std::chrono::milliseconds(600);
        for (auto now = Clock::now(); now < deadline; now = Clock::now()) {
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                      now);
            const int ready =
                poll_socket(&pending, static_cast<int>(remaining.count()) + 1);
            if (ready < 0 && socket_interrupted()) {
                continue;
            }
            if (ready < 0 || (ready > 0 && !(pending.revents & POLLIN))) {
                throw std::runtime_error(
                    "waiting for discovery replies failed");
            }
            if (ready == 0) {
                break;
            }
            char buffer[256];
            sockaddr_in sender{};
            SocketLength size = sizeof(sender);
            const auto received =
                recvfrom(socket.get(), buffer, sizeof(buffer), receive_flags,
                         reinterpret_cast<sockaddr*>(&sender), &size);
            if (received <= 0 ||
                received > static_cast<int>(sizeof(buffer))) {
                continue;
            }
            RemoteTarget target{};
            if (!read_offer(
                    std::string(buffer, static_cast<std::size_t>(received)),
                    nonce, sender, target)) {
                continue;
            }
            const auto duplicate = std::find_if(
                devices.begin(), devices.end(),
                [&](const RemoteTarget& device) {
                    return device.fingerprint == target.fingerprint;
                });
            if (duplicate == devices.end()) {
                devices.push_back(std::move(target));
                if (devices.size() == 2) {
                    return devices;
                }
            }
        }
    }
    return devices;
}
