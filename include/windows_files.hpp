#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <fcntl.h>
#include <io.h>
#include <openssl/rand.h>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace netpanel_windows {

inline void file_error(const char* operation) {
    throw std::system_error(GetLastError(), std::system_category(), operation);
}

inline std::string user_sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        file_error("opening current user token");
    }
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> buffer(size);
    const bool read = GetTokenInformation(token, TokenUser, buffer.data(), size, &size) != 0;
    const DWORD error = GetLastError();
    CloseHandle(token);
    if (!read) throw std::system_error(error, std::system_category(), "reading current user token");
    char* text = nullptr;
    if (!ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text)) {
        file_error("reading current user SID");
    }
    const std::string result(text);
    LocalFree(text);
    return result;
}

inline int create_private_temp(const char* prefix, std::string& path) {
    const auto sddl = "D:P(A;;FA;;;SY)(A;;FA;;;" + user_sid() + ")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        file_error("creating private file permissions");
    }
    const std::unique_ptr<void, decltype(&LocalFree)> security(descriptor, &LocalFree);
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    for (int attempt = 0; attempt < 64; ++attempt) {
        unsigned char bytes[16];
        if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
            throw std::runtime_error("generating temporary file name failed");
        }
        constexpr char hex[] = "0123456789abcdef";
        path = prefix;
        for (unsigned char byte : bytes) {
            path += hex[byte >> 4];
            path += hex[byte & 15];
        }
        HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_FILE_EXISTS) continue;
            file_error("creating private temporary file");
        }
        const int fd = _open_osfhandle(reinterpret_cast<std::intptr_t>(handle),
                                       _O_RDWR | _O_BINARY | _O_NOINHERIT);
        if (fd < 0) {
            CloseHandle(handle);
            DeleteFileA(path.c_str());
            throw std::runtime_error("opening private temporary file stream failed");
        }
        return fd;
    }
    throw std::runtime_error("creating unique temporary file failed");
}

inline void check_private_file(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) file_error("checking identity file");
    if (GetFileType(handle) != FILE_TYPE_DISK ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
        throw std::runtime_error("device identity must be a regular file");
    }
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD error = GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                        nullptr, nullptr, &acl, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) {
        throw std::system_error(error, std::system_category(), "checking device identity permissions");
    }
    const std::unique_ptr<void, decltype(&LocalFree)> security(descriptor, &LocalFree);
    if (!acl) throw std::runtime_error("device identity has unrestricted permissions");
    const auto current_user = user_sid();
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void* entry = nullptr;
        if (!GetAce(acl, index, &entry)) file_error("checking device identity permissions");
        const auto* header = static_cast<ACE_HEADER*>(entry);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
        char* text = nullptr;
        if (!ConvertSidToStringSidA(&ace->SidStart, &text)) file_error("reading identity permissions");
        const std::string sid(text);
        LocalFree(text);
        if (sid != current_user && sid != "S-1-5-18") {
            throw std::runtime_error("device identity must have owner-only permissions");
        }
    }
}

} // namespace netpanel_windows
#endif
