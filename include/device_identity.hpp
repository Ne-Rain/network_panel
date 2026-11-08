#ifndef NETPANEL_DEVICE_IDENTITY_HPP
#define NETPANEL_DEVICE_IDENTITY_HPP

#include <openssl/types.h>

#include <string>

struct DeviceIdentity {
    std::string pem_path;
    std::string fingerprint;
};

// Loads certs/device-identity.pem relative to the process working directory.
// Creates the identity on first use and throws on I/O or validation errors.
DeviceIdentity load_or_create_device_identity();

// Checks the validity period and the SHA-256 fingerprint of a TLS peer certificate.
bool matches_device_certificate(const X509* certificate, const std::string& expected_fingerprint);

#endif
