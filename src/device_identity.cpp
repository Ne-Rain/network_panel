#include "device_identity.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr char identity_directory[] = "certs";
constexpr char identity_path[] = "certs/device-identity.pem";

struct CloseFile {
    void operator()(FILE* file) const { std::fclose(file); }
};

using File = std::unique_ptr<FILE, CloseFile>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;

[[noreturn]] void throw_system_error(const char* message) {
    throw std::system_error(errno, std::generic_category(), message);
}

File open_stream(int fd, const char* mode) {
    File file(fdopen(fd, mode));
    if (!file) {
        const int error = errno;
        close(fd);
        throw std::system_error(error, std::generic_category(), "opening identity stream");
    }
    return file;
}

int reject_password_prompt(char*, int, int, void*) { return -1; }

std::string fingerprint_of(const X509* cert) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &size) != 1) {
        throw std::runtime_error("computing device certificate fingerprint failed");
    }

    constexpr char hex[] = "0123456789abcdef";
    std::string fingerprint;
    fingerprint.reserve(size * 2);
    for (unsigned int i = 0; i < size; ++i) {
        fingerprint += hex[digest[i] >> 4];
        fingerprint += hex[digest[i] & 0x0f];
    }
    return fingerprint;
}

bool certificate_is_current(const X509* cert) {
    return X509_cmp_current_time(X509_get0_notBefore(cert)) < 0 && X509_cmp_current_time(X509_get0_notAfter(cert)) > 0;
}

bool read_identity(std::string& fingerprint) {
    const int fd = open(identity_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) {
            return false;
        }
        throw_system_error("opening certs/device-identity.pem");
    }
    auto file = open_stream(fd, "rb");

    struct stat info {};
    if (fstat(fd, &info) != 0) {
        throw_system_error("checking certs/device-identity.pem");
    }
    if (!S_ISREG(info.st_mode) || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        throw std::runtime_error("device identity must be a regular file with owner-only permissions");
    }

    Certificate cert(PEM_read_X509(file.get(), nullptr, nullptr, nullptr), &X509_free);
    Key key(PEM_read_PrivateKey(file.get(), nullptr, reject_password_prompt, nullptr), &EVP_PKEY_free);
    if (!cert || !key) {
        throw std::runtime_error("reading certificate and private key from device identity failed");
    }
    if (X509_check_private_key(cert.get(), key.get()) != 1) {
        throw std::runtime_error("device certificate and private key do not match");
    }
    if (X509_NAME_cmp(X509_get_subject_name(cert.get()), X509_get_issuer_name(cert.get())) != 0 ||
        X509_verify(cert.get(), key.get()) != 1) {
        throw std::runtime_error("device certificate is not correctly self-signed");
    }
    if (!certificate_is_current(cert.get())) {
        throw std::runtime_error("device certificate is outside its validity period");
    }

    fingerprint = fingerprint_of(cert.get());
    return true;
}

void create_identity() {
    Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", std::size_t{2048}), &EVP_PKEY_free);
    Certificate cert(X509_new(), &X509_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> serial(BN_new(), &BN_free);
    if (!key || !cert || !serial) {
        throw std::runtime_error("creating device certificate or key failed");
    }

    auto* subject = X509_get_subject_name(cert.get());
    constexpr unsigned char common_name[] = "NetPanel Device";
    constexpr long validity_seconds = 3650L * 24 * 60 * 60;
    if (!subject || X509_set_version(cert.get(), 2) != 1 ||
        BN_rand(serial.get(), 128, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1 ||
        !BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(cert.get())) ||
        !X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), validity_seconds) ||
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name, -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert.get(), subject) != 1 || X509_set_pubkey(cert.get(), key.get()) != 1 ||
        X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0) {
        throw std::runtime_error("signing device certificate failed");
    }

    char temporary_path[] = "certs/.device-identity-XXXXXX";
    const int fd = mkstemp(temporary_path);
    if (fd < 0) {
        throw_system_error("creating temporary device identity");
    }

    try {
        auto file = open_stream(fd, "wb");
        if (PEM_write_X509(file.get(), cert.get()) != 1 ||
            PEM_write_PrivateKey(file.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            throw std::runtime_error("writing device certificate and key failed");
        }
        if (std::fflush(file.get()) != 0 || fsync(fd) != 0) {
            throw_system_error("flushing device identity");
        }
        if (std::fclose(file.release()) != 0) {
            throw_system_error("closing device identity");
        }

        // If another process already published an identity, use that identity.
        if (link(temporary_path, identity_path) != 0 && errno != EEXIST) {
            throw_system_error("publishing certs/device-identity.pem");
        }
    } catch (...) {
        unlink(temporary_path);
        throw;
    }
    unlink(temporary_path);
}

} // namespace

DeviceIdentity load_or_create_device_identity() {
    if (mkdir(identity_directory, 0700) != 0 && errno != EEXIST) {
        throw_system_error("creating certs directory");
    }
    struct stat directory_info {};
    if (lstat(identity_directory, &directory_info) != 0) {
        throw_system_error("checking certs directory");
    }
    if (!S_ISDIR(directory_info.st_mode)) {
        throw std::runtime_error("certs must be a directory");
    }

    std::string fingerprint;
    if (!read_identity(fingerprint)) {
        create_identity();
        if (!read_identity(fingerprint)) {
            throw std::runtime_error("device identity disappeared after publication");
        }
    }
    return {identity_path, std::move(fingerprint)};
}

bool matches_device_certificate(const X509* certificate, const std::string& expected_fingerprint) {
    if (!certificate || !certificate_is_current(certificate)) {
        return false;
    }
    try {
        return fingerprint_of(certificate) == expected_fingerprint;
    } catch (const std::runtime_error&) {
        return false;
    }
}
