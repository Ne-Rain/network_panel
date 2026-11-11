#include "file_catalog.hpp"
#include <cctype>
#include <climits>
#include <cstddef>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

static const std::unordered_map<std::string, FileType> FILE_TYPES = {
    {"txt", FileType::File},    {"csv", FileType::File},    {"pdf", FileType::File},
    {"pfd", FileType::File},    {"doc", FileType::File},    {"docx", FileType::File},
    {"xls", FileType::File},    {"xlsx", FileType::File},   {"ppt", FileType::File},
    {"pptx", FileType::File},   {"md", FileType::File},

    {"jpg", FileType::Image},   {"jpeg", FileType::Image},  {"png", FileType::Image},
    {"gif", FileType::Image},   {"webp", FileType::Image},  {"bmp", FileType::Image},
    {"svg", FileType::Image},   {"heic", FileType::Image},

    {"mp4", FileType::Video},   {"mov", FileType::Video},   {"mkv", FileType::Video},
    {"avi", FileType::Video},   {"webm", FileType::Video},  {"m4v", FileType::Video},

    {"mp3", FileType::Audio},   {"wav", FileType::Audio},   {"flac", FileType::Audio},
    {"aac", FileType::Audio},   {"m4a", FileType::Audio},   {"ogg", FileType::Audio},
    {"opus", FileType::Audio},

    {"zip", FileType::Archive}, {"rar", FileType::Archive}, {"7z", FileType::Archive},
    {"tar", FileType::Archive}, {"gz", FileType::Archive},  {"bz2", FileType::Archive},
    {"xz", FileType::Archive},  {"zst", FileType::Archive},
};

void parse_file_type(const std::string& token, FileType& result) {
    if (token == "file") {
        result = FileType::File;
    } else if (token == "image") {
        result = FileType::Image;
    } else if (token == "video") {
        result = FileType::Video;
    } else if (token == "audio") {
        result = FileType::Audio;
    } else if (token == "archive") {
        result = FileType::Archive;
    } else {
        result = FileType::Other;
    }
}

std::string file_type_to_string(FileType type) {
    switch (type) {
    case FileType::File:
        return "file";
    case FileType::Image:
        return "image";
    case FileType::Video:
        return "video";
    case FileType::Audio:
        return "audio";
    case FileType::Archive:
        return "archive";
    case FileType::Other:
        return "other";
    }
    throw std::invalid_argument("invalid FileType");
}

std::unordered_map<std::size_t, FileRecord> load_files(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("file open failed");
    }
    std::unordered_map<std::size_t, FileRecord> file_list;
    std::string line;
    std::size_t line_id = 0;
    while (std::getline(in, line)) {
        // 跳过空行，以及只包含空格、Tab、回车的行
        if (line.find_first_not_of(" \t\r") == std::string::npos) {
            continue;
        }
        ++line_id;
        FileRecord file_record;
        std::string file_type;
        std::istringstream iss(line);
        if (!(iss >> file_record.file_id >> std::quoted(file_record.display_name)
              >> file_record.size_bytes >> file_type >> std::quoted(file_record.uploadedAt)
              >> file_record.owner_group >> file_record.storage_path)) {
            throw std::runtime_error("line_id: " + std::to_string(line_id) + " is illegal");
        }
        parse_file_type(file_type, file_record.type);
        std::string tmp;
        if (iss >> tmp) { // 判断是否有多余字段
            throw std::runtime_error("line_id: " + std::to_string(line_id) + " is illegal");
        }
        if (file_list.find(file_record.file_id) != file_list.end()) {
            throw std::runtime_error("line_id: " + std::to_string(line_id) + " is already existed");
        }
        file_list.emplace(file_record.file_id, file_record);
    }
    if (in.bad()) { // 读取文件发生IO错误
        throw std::runtime_error("Failed to read account file: " + path);
    }
    return file_list;
}

std::vector<FileRecord>
get_group_file_list(const std::unordered_map<std::size_t, FileRecord>& file_list,
                    std::string group) {
    std::vector<FileRecord> group_file_list;
    for (const auto file_record : file_list) {
        if (file_record.second.owner_group == group || file_record.second.owner_group == "PUBLIC") {
            group_file_list.push_back(file_record.second);
        }
    }
    return group_file_list;
}

FileType get_file_type(const std::string& file_name) {
    const auto dot = file_name.rfind('.');
    FileType result;
    if (dot != std::string::npos && dot != 0 && dot + 1 < file_name.size()) {
        std::string extension = file_name.substr(dot + 1);
        for (char& ch : extension) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        const auto it = FILE_TYPES.find(extension);
        return it == FILE_TYPES.end() ? FileType::Other : it->second;
    } else {
        result = FileType::Other;
    }
    return result;
}