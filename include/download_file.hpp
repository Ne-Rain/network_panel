#pragma once
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

// Owns the exclusive temporary file until it has been published without overwrite.
class DownloadFile {
public:
    explicit DownloadFile(const std::string& path) {
        if (path.empty() || path.find('\0') != std::string::npos)
            throw std::invalid_argument("Invalid download destination");
#ifdef _WIN32
        target_ = widen(path);
        if (target_.size() < 4 || !((target_[0] >= L'A' && target_[0] <= L'Z') ||
            (target_[0] >= L'a' && target_[0] <= L'z')) || target_[1] != L':' ||
            (target_[2] != L'\\' && target_[2] != L'/'))
            throw std::invalid_argument("Use an absolute drive path for downloads");
        for (auto& c : target_) if (c == L'/') c = L'\\';
        std::size_t begin = 3;
        while (begin <= target_.size()) {
            const auto end = target_.find(L'\\', begin);
            const auto part = target_.substr(begin, end == std::wstring::npos ? end : end - begin);
            if (part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
                part.back() == L' ' || part.find_first_of(L"<>:\"|?*") != std::wstring::npos)
                throw std::invalid_argument("Invalid download path component");
            for (auto c : part) if (c < 32) throw std::invalid_argument("Invalid download path character");
            auto stem = part.substr(0, part.find(L'.'));
            for (auto& c : stem) if (c >= L'a' && c <= L'z') c -= L'a' - L'A';
            if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
                (stem.size() == 4 && (stem.substr(0, 3) == L"COM" || stem.substr(0, 3) == L"LPT") && stem[3] >= L'1' && stem[3] <= L'9'))
                throw std::invalid_argument("Reserved Windows filename");
            if (end == std::wstring::npos) break;
            begin = end + 1;
        }
        const DWORD attr = GetFileAttributesW(target_.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES)
            throw std::system_error(std::make_error_code(std::errc::file_exists));
        const DWORD attr_error = GetLastError();
        if (attr_error != ERROR_FILE_NOT_FOUND && attr_error != ERROR_PATH_NOT_FOUND)
            throw std::system_error(attr_error, std::system_category(), "Checking download destination");
        const auto parent = target_.substr(0, target_.find_last_of(L'\\') + 1);
        std::random_device random;
        HANDLE handle = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 32; ++attempt) {
            temp_ = parent + L".netpanel-download-" + std::to_wstring(random()) +
                L"-" + std::to_wstring(random()) + L".part";
            handle = CreateFileW(temp_.c_str(), GENERIC_WRITE, 0, nullptr,
                                 CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle != INVALID_HANDLE_VALUE) break;
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
                throw std::system_error(error, std::system_category(), "Creating download temporary file");
        }
        if (handle == INVALID_HANDLE_VALUE)
            throw std::system_error(std::make_error_code(std::errc::file_exists));
        const int fd = _open_osfhandle(reinterpret_cast<std::intptr_t>(handle), _O_WRONLY | _O_BINARY | _O_NOINHERIT);
        if (fd == -1) {
            const int error = errno;
            CloseHandle(handle); DeleteFileW(temp_.c_str());
            throw std::system_error(error, std::generic_category(), "Opening download file descriptor");
        }
        file_ = _fdopen(fd, "wb");
        if (!file_) {
            const int error = errno;
            _close(fd); DeleteFileW(temp_.c_str());
            throw std::system_error(error, std::generic_category(), "Opening download stream");
        }
#else
        if (path.front() != '/' || path.back() == '/')
            throw std::invalid_argument("Use an absolute file path for downloads");
        target_ = path;
        const auto leaf = path.substr(path.find_last_of('/') + 1);
        if (leaf == "." || leaf == "..") throw std::invalid_argument("Invalid download filename");
        std::string pattern = path.substr(0, path.find_last_of('/') + 1) + ".netpanel-download-XXXXXX";
        std::vector<char> name(pattern.begin(), pattern.end()); name.push_back('\0');
        const int fd = ::mkstemp(name.data());
        if (fd == -1) throw std::system_error(errno, std::generic_category(), "Creating download temporary file");
        temp_ = name.data();
        file_ = ::fdopen(fd, "wb");
        if (!file_) {
            const int error = errno;
            ::close(fd); ::unlink(temp_.c_str());
            throw std::system_error(error, std::generic_category(), "Opening download stream");
        }
#endif
    }
    DownloadFile(const DownloadFile&) = delete;
    DownloadFile& operator=(const DownloadFile&) = delete;
    ~DownloadFile() {
        if (file_) std::fclose(file_);
#ifdef _WIN32
        if (!temp_.empty()) DeleteFileW(temp_.c_str());
#else
        if (!temp_.empty()) ::unlink(temp_.c_str());
#endif
    }
    bool write(const char* data, std::size_t size) {
        return file_ && std::fwrite(data, 1, size, file_) == size;
    }
    void publish() {
        if (!file_) throw std::logic_error("Download stream already closed");
        const bool flushed = std::fflush(file_) == 0;
        const bool closed = std::fclose(file_) == 0;
        file_ = nullptr;
        if (!flushed || !closed)
            throw std::system_error(std::make_error_code(std::errc::io_error), "Closing download stream");
#ifdef _WIN32
        // Deliberately omit MOVEFILE_REPLACE_EXISTING, including for a late collision.
        if (!MoveFileExW(temp_.c_str(), target_.c_str(), 0)) {
            const DWORD error = GetLastError();
            if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)
                throw std::system_error(std::make_error_code(std::errc::file_exists));
            throw std::system_error(error, std::system_category(), "Publishing download");
        }
        temp_.clear();
#else
        // Same-directory hard link gives atomic no-replace publication on Linux.
        if (::link(temp_.c_str(), target_.c_str()) != 0)
            throw std::system_error(errno, std::generic_category(), "Publishing download");
        if (::unlink(temp_.c_str()) == 0) temp_.clear();
#endif
    }
private:
    std::FILE* file_ = nullptr;
#ifdef _WIN32
    std::wstring target_, temp_;
    static std::wstring widen(const std::string& path) {
        if (path.size() > static_cast<std::size_t>(INT_MAX)) throw std::invalid_argument("Path too long");
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), nullptr, 0);
        if (length <= 0) throw std::invalid_argument("Path is not valid UTF-8");
        std::wstring wide(length, L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), &wide[0], length) != length)
            throw std::invalid_argument("Path is not valid UTF-8");
        return wide;
    }
#else
    std::string target_, temp_;
#endif
};


