#ifndef NETPANEL_DEVICE_DISCOVERY_HPP
#define NETPANEL_DEVICE_DISCOVERY_HPP

#include <atomic>
#include <string>
#include <thread>
#include <vector>

struct RemoteTarget {
    std::string host;
    int port;
    std::string fingerprint;
    std::string name;
};

class DiscoveryResponder {
public:
    DiscoveryResponder(int https_port, const std::string& fingerprint);
    ~DiscoveryResponder();

    DiscoveryResponder(const DiscoveryResponder&) = delete;
    DiscoveryResponder& operator=(const DiscoveryResponder&) = delete;

private:
    void respond(const std::string& endpoint);

    int socket_ = -1;
    std::atomic<bool> stopping_{false};
    std::thread worker_;
};

std::vector<RemoteTarget> discover_servers();

#endif
